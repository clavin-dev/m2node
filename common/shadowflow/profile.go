// Package shadowflow implements the TLS Record Size camouflage engine
// and ShadowStream transport protocol for the ShadowFlow proxy.
//
// The camouflage engine reshapes TLS record sizes to match real browser
// traffic distributions, eliminating statistical fingerprints that GFW
// uses for detection (e.g., the "19-byte" Vision signature).
//
// ShadowStream is a custom multiplexed transport that sits inside TLS
// and produces zero protocol-level fingerprints.
package shadowflow

import (
	"math/rand"
	"sync"
)

// ====================================================================
// Traffic Profiles — sampled from real browser captures
// ====================================================================

// SizeRange defines a weighted range for TLS record payload sizes.
// Weight controls how often this range is selected during sampling.
type SizeRange struct {
	Min    int // minimum TLS record payload size (bytes)
	Max    int // maximum TLS record payload size (bytes)
	Weight int // selection weight (higher = more frequent)
}

// InitialPacket defines a specific packet in the handshake sequence.
type InitialPacket struct {
	MinSize int // minimum size for this position
	MaxSize int // maximum size for this position
}

// TrafficProfile models real-world TLS traffic characteristics.
// Profiles are built from actual pcap data of real browsers.
type TrafficProfile struct {
	Name string

	// C2S / S2C packet size distributions (after initial phase)
	C2SSizes []SizeRange
	S2CSizes []SizeRange

	// Initial handshake sequence (first N packets after TLS handshake)
	// These are critical — VLESS+Vision was caught primarily here
	C2SInitial []InitialPacket
	S2CInitial []InitialPacket

	// Minimum payload size for any record (eliminates "19-byte" fingerprint)
	MinRecordPayload int

	// Maximum TLS record payload size (RFC 8449: max 16384)
	MaxRecordPayload int
}

// Pre-built profiles from real pcap analysis
var (
	// ChromeH2Profile — Chrome 120+ browsing Google services over HTTP/2
	// Captured from: Chrome → google.com, youtube.com, gmail.com
	// Key characteristics:
	//   - Large Client Hello (~1700 bytes)
	//   - Varied C→S sizes (HEADERS, DATA, WINDOW_UPDATE frames)
	//   - S→C dominated by large data frames (14000-16384)
	//   - Minimum observed record: 26 bytes (WINDOW_UPDATE)
	ChromeH2Profile = &TrafficProfile{
		Name: "chrome_h2",
		C2SSizes: []SizeRange{
			{Min: 26, Max: 120, Weight: 25},    // WINDOW_UPDATE, PING, small HEADERS
			{Min: 121, Max: 500, Weight: 30},    // Medium HEADERS, small DATA
			{Min: 501, Max: 1200, Weight: 25},   // Larger HEADERS with cookies
			{Min: 1201, Max: 4000, Weight: 12},  // POST bodies, large requests
			{Min: 4001, Max: 16384, Weight: 8},  // File uploads, large payloads
		},
		S2CSizes: []SizeRange{
			{Min: 26, Max: 100, Weight: 10},     // SETTINGS_ACK, PING_ACK, WINDOW_UPDATE
			{Min: 101, Max: 500, Weight: 15},    // Small responses, HEADERS
			{Min: 501, Max: 2000, Weight: 15},   // Medium responses, JSON APIs
			{Min: 2001, Max: 8000, Weight: 20},  // Larger responses, HTML pages
			{Min: 8001, Max: 14000, Weight: 20}, // Large data, images
			{Min: 14001, Max: 16384, Weight: 20},// Maximum TLS records (common for streaming)
		},
		// Chrome H2 initial sequence after TLS handshake:
		// 1. HTTP/2 connection preface + SETTINGS (magic + settings frame)
		// 2. WINDOW_UPDATE (connection-level)
		// 3. HEADERS (first request)
		// 4. DATA (if POST) or nothing
		C2SInitial: []InitialPacket{
			{MinSize: 60, MaxSize: 120},   // H2 SETTINGS frame
			{MinSize: 26, MaxSize: 50},    // WINDOW_UPDATE
			{MinSize: 150, MaxSize: 800},  // HEADERS (first GET request)
			{MinSize: 26, MaxSize: 100},   // WINDOW_UPDATE / PRIORITY
		},
		// Server response initial sequence:
		// 1. SETTINGS + SETTINGS_ACK
		// 2. WINDOW_UPDATE
		// 3. HEADERS (response headers)
		// 4. DATA (response body, usually large)
		S2CInitial: []InitialPacket{
			{MinSize: 80, MaxSize: 200},     // SETTINGS
			{MinSize: 26, MaxSize: 50},      // WINDOW_UPDATE
			{MinSize: 100, MaxSize: 600},    // HEADERS (response)
			{MinSize: 2000, MaxSize: 16384}, // DATA (first chunk, usually large)
		},
		MinRecordPayload: 26,    // Never produce records smaller than this
		MaxRecordPayload: 16384, // TLS maximum
	}

	// SafariProfile — Safari on macOS/iOS browsing Apple services
	// Key: larger initial packets, different size distribution
	SafariProfile = &TrafficProfile{
		Name: "safari",
		C2SSizes: []SizeRange{
			{Min: 30, Max: 150, Weight: 20},
			{Min: 151, Max: 600, Weight: 30},
			{Min: 601, Max: 1500, Weight: 25},
			{Min: 1501, Max: 5000, Weight: 15},
			{Min: 5001, Max: 16384, Weight: 10},
		},
		S2CSizes: []SizeRange{
			{Min: 30, Max: 200, Weight: 10},
			{Min: 201, Max: 1000, Weight: 15},
			{Min: 1001, Max: 4000, Weight: 20},
			{Min: 4001, Max: 10000, Weight: 25},
			{Min: 10001, Max: 16384, Weight: 30},
		},
		C2SInitial: []InitialPacket{
			{MinSize: 80, MaxSize: 200},
			{MinSize: 30, MaxSize: 60},
			{MinSize: 200, MaxSize: 1000},
			{MinSize: 30, MaxSize: 120},
		},
		S2CInitial: []InitialPacket{
			{MinSize: 100, MaxSize: 300},
			{MinSize: 30, MaxSize: 60},
			{MinSize: 150, MaxSize: 800},
			{MinSize: 3000, MaxSize: 16384},
		},
		MinRecordPayload: 30,
		MaxRecordPayload: 16384,
	}

	// FirefoxProfile — Firefox browsing general websites
	FirefoxProfile = &TrafficProfile{
		Name: "firefox",
		C2SSizes: []SizeRange{
			{Min: 28, Max: 100, Weight: 20},
			{Min: 101, Max: 450, Weight: 30},
			{Min: 451, Max: 1100, Weight: 25},
			{Min: 1101, Max: 3500, Weight: 15},
			{Min: 3501, Max: 16384, Weight: 10},
		},
		S2CSizes: []SizeRange{
			{Min: 28, Max: 150, Weight: 10},
			{Min: 151, Max: 800, Weight: 15},
			{Min: 801, Max: 3000, Weight: 20},
			{Min: 3001, Max: 10000, Weight: 25},
			{Min: 10001, Max: 16384, Weight: 30},
		},
		C2SInitial: []InitialPacket{
			{MinSize: 70, MaxSize: 150},
			{MinSize: 28, MaxSize: 55},
			{MinSize: 180, MaxSize: 750},
			{MinSize: 28, MaxSize: 90},
		},
		S2CInitial: []InitialPacket{
			{MinSize: 90, MaxSize: 250},
			{MinSize: 28, MaxSize: 55},
			{MinSize: 120, MaxSize: 700},
			{MinSize: 2500, MaxSize: 16384},
		},
		MinRecordPayload: 28,
		MaxRecordPayload: 16384,
	}

	// ================================================================
	// 中国大厂流量画像 — 伪装为国内最常见的应用流量
	// GFW 不可能封锁自家流量，这是最安全的伪装身份
	// ================================================================

	// DouyinProfile — 抖音短视频刷视频流量
	// 特征: 频繁的小上行(滑动/点赞/心跳) + 中等下行(2-5秒短视频片段)
	// 短视频不像长视频那样持续大包，而是突发性中等包
	DouyinProfile = &TrafficProfile{
		Name: "douyin",
		C2SSizes: []SizeRange{
			{Min: 26, Max: 80, Weight: 40},     // 心跳、滑动事件、点赞
			{Min: 81, Max: 250, Weight: 25},     // 评论发送、搜索请求
			{Min: 251, Max: 600, Weight: 20},    // 用户行为上报、广告回传
			{Min: 601, Max: 1500, Weight: 10},   // 视频上传元数据、封面
			{Min: 1501, Max: 4000, Weight: 5},   // 偶尔的大上行(发布视频)
		},
		S2CSizes: []SizeRange{
			{Min: 26, Max: 150, Weight: 8},       // ACK、推送通知
			{Min: 151, Max: 800, Weight: 10},     // 用户信息、评论列表
			{Min: 801, Max: 4000, Weight: 15},    // 商品卡片、推荐列表 JSON
			{Min: 4001, Max: 10000, Weight: 30},  // ★ 短视频片段(2-3秒, 主流)
			{Min: 10001, Max: 16384, Weight: 37}, // ★ 高清短视频片段(4-5秒)
		},
		C2SInitial: []InitialPacket{
			{MinSize: 60, MaxSize: 130},   // H2 SETTINGS
			{MinSize: 26, MaxSize: 50},    // WINDOW_UPDATE
			{MinSize: 300, MaxSize: 900},  // 首次推荐请求(带设备信息)
			{MinSize: 26, MaxSize: 80},    // ACK
		},
		S2CInitial: []InitialPacket{
			{MinSize: 80, MaxSize: 200},      // SETTINGS
			{MinSize: 26, MaxSize: 50},       // WINDOW_UPDATE
			{MinSize: 800, MaxSize: 3000},    // 推荐列表 JSON
			{MinSize: 6000, MaxSize: 16384},  // 首个视频片段预加载
		},
		MinRecordPayload: 26,
		MaxRecordPayload: 16384,
	}

	// BilibiliProfile — B站视频/直播流量
	// 特征: 长视频持续大包 + 弹幕小包穿插 + 偶尔的评论/互动
	// 与抖音区别: 持续时间更长，下行比例更高
	BilibiliProfile = &TrafficProfile{
		Name: "bilibili",
		C2SSizes: []SizeRange{
			{Min: 26, Max: 60, Weight: 35},      // 弹幕心跳、播放器状态
			{Min: 61, Max: 200, Weight: 25},      // 发弹幕、点赞、投币
			{Min: 201, Max: 600, Weight: 20},     // 评论、搜索、换P
			{Min: 601, Max: 1500, Weight: 15},    // 质量切换请求、历史上报
			{Min: 1501, Max: 4000, Weight: 5},    // 稍大的请求
		},
		S2CSizes: []SizeRange{
			{Min: 26, Max: 100, Weight: 5},        // 弹幕 ACK
			{Min: 101, Max: 500, Weight: 8},       // 弹幕数据包(单条弹幕很小)
			{Min: 501, Max: 2000, Weight: 7},      // 批量弹幕、评论列表
			{Min: 2001, Max: 10000, Weight: 15},   // 中等视频分片
			{Min: 10001, Max: 16384, Weight: 65},  // ★★ 视频数据(B站长视频为主)
		},
		C2SInitial: []InitialPacket{
			{MinSize: 60, MaxSize: 120},
			{MinSize: 26, MaxSize: 50},
			{MinSize: 250, MaxSize: 700},   // 视频播放请求(带 bvid 等)
			{MinSize: 26, MaxSize: 100},
		},
		S2CInitial: []InitialPacket{
			{MinSize: 80, MaxSize: 200},
			{MinSize: 26, MaxSize: 50},
			{MinSize: 400, MaxSize: 2000},     // 播放信息 JSON
			{MinSize: 10000, MaxSize: 16384},  // 首个视频分片
		},
		MinRecordPayload: 26,
		MaxRecordPayload: 16384,
	}

	// AppleMusicProfile — Apple Music 音乐流媒体
	// 特征: 持续中等大小下行(音频分片 AAC/ALAC 256kbps-24bit)
	// + 小上行(播放控制/歌词请求) + 间歇性大包(专辑封面/歌词动画)
	// 与视频的区别: 包更小更均匀，因为音频码率比视频低得多
	AppleMusicProfile = &TrafficProfile{
		Name: "apple_music",
		C2SSizes: []SizeRange{
			{Min: 26, Max: 80, Weight: 35},      // 播放心跳、进度上报、暂停/继续
			{Min: 81, Max: 250, Weight: 30},      // 搜索请求、歌曲切换、收藏
			{Min: 251, Max: 600, Weight: 20},     // 播放列表操作、歌词请求
			{Min: 601, Max: 1500, Weight: 10},    // 库同步、推荐反馈
			{Min: 1501, Max: 3000, Weight: 5},    // 偏好设置上传
		},
		S2CSizes: []SizeRange{
			{Min: 26, Max: 100, Weight: 8},        // ACK、控制响应
			{Min: 101, Max: 500, Weight: 10},      // 歌曲元数据、歌词文本
			{Min: 501, Max: 2000, Weight: 15},     // 音频分片(AAC 256kbps, 约0.5秒)
			{Min: 2001, Max: 6000, Weight: 35},    // ★ 音频分片(主流大小, 1-2秒 AAC)
			{Min: 6001, Max: 16384, Weight: 32},   // ★ 无损音频/专辑封面图片
		},
		C2SInitial: []InitialPacket{
			{MinSize: 60, MaxSize: 130},     // H2 SETTINGS
			{MinSize: 26, MaxSize: 50},      // WINDOW_UPDATE
			{MinSize: 200, MaxSize: 600},    // 首次播放请求(带认证信息)
			{MinSize: 26, MaxSize: 80},      // ACK
		},
		S2CInitial: []InitialPacket{
			{MinSize: 80, MaxSize: 200},
			{MinSize: 26, MaxSize: 50},
			{MinSize: 300, MaxSize: 1200},     // 播放列表/歌曲信息 JSON
			{MinSize: 2000, MaxSize: 8000},    // 首个音频分片预加载
		},
		MinRecordPayload: 26,
		MaxRecordPayload: 16384,
	}

	// TaobaoProfile — 淘宝/天猫购物浏览
	// 特征: 频繁中等下行(商品图片) + 小上行(搜索/点击/滑动)
	// 大量并发小请求，图片为主
	TaobaoProfile = &TrafficProfile{
		Name: "taobao",
		C2SSizes: []SizeRange{
			{Min: 26, Max: 100, Weight: 30},     // 滑动事件、曝光上报
			{Min: 101, Max: 400, Weight: 30},    // 搜索请求、商品详情请求
			{Min: 401, Max: 1000, Weight: 25},   // 筛选/排序、购物车操作
			{Min: 1001, Max: 3000, Weight: 10},  // 下单请求(带地址等)
			{Min: 3001, Max: 8000, Weight: 5},   // 偶尔的大请求
		},
		S2CSizes: []SizeRange{
			{Min: 26, Max: 200, Weight: 10},      // ACK、小通知
			{Min: 201, Max: 1000, Weight: 15},    // 搜索建议、小 JSON
			{Min: 1001, Max: 4000, Weight: 25},   // ★ 商品列表 JSON
			{Min: 4001, Max: 10000, Weight: 30},  // ★ 商品图片(webp 压缩)
			{Min: 10001, Max: 16384, Weight: 20}, // 大图、详情页资源
		},
		C2SInitial: []InitialPacket{
			{MinSize: 60, MaxSize: 120},
			{MinSize: 26, MaxSize: 50},
			{MinSize: 300, MaxSize: 800},   // 首页请求(带用户态)
			{MinSize: 26, MaxSize: 100},
		},
		S2CInitial: []InitialPacket{
			{MinSize: 80, MaxSize: 200},
			{MinSize: 26, MaxSize: 50},
			{MinSize: 1000, MaxSize: 4000},   // 首页推荐 JSON
			{MinSize: 3000, MaxSize: 12000},  // 首屏商品图片
		},
		MinRecordPayload: 26,
		MaxRecordPayload: 16384,
	}

	// ICloudSyncProfile — iCloud 同步(照片/备份/文档)
	// 特征: 超大双向流量，持续满包传输
	// 照片备份时上行为主，恢复时下行为主
	// 这是大流量场景最好的伪装 — iCloud 传文件本来就是跑满带宽
	ICloudSyncProfile = &TrafficProfile{
		Name: "icloud_sync",
		C2SSizes: []SizeRange{
			{Min: 30, Max: 100, Weight: 8},       // 心跳、同步状态查询
			{Min: 101, Max: 500, Weight: 7},      // 文件元数据、目录列表
			{Min: 501, Max: 4000, Weight: 10},    // 小文件上传、校验和
			{Min: 4001, Max: 12000, Weight: 30},  // ★ 照片上传分片(HEIC 压缩)
			{Min: 12001, Max: 16384, Weight: 45}, // ★★ 大文件/视频备份(满包)
		},
		S2CSizes: []SizeRange{
			{Min: 30, Max: 100, Weight: 5},        // ACK、同步确认
			{Min: 101, Max: 500, Weight: 5},       // 进度回复、元数据
			{Min: 501, Max: 4000, Weight: 8},      // 文件列表响应、冲突解决
			{Min: 4001, Max: 12000, Weight: 22},   // ★ 下载分片
			{Min: 12001, Max: 16384, Weight: 60},  // ★★★ 照片/文件下载(满包主导)
		},
		C2SInitial: []InitialPacket{
			{MinSize: 60, MaxSize: 150},
			{MinSize: 30, MaxSize: 60},
			{MinSize: 300, MaxSize: 1200},    // Apple ID 认证 + 同步状态
			{MinSize: 100, MaxSize: 500},
		},
		S2CInitial: []InitialPacket{
			{MinSize: 80, MaxSize: 250},
			{MinSize: 30, MaxSize: 60},
			{MinSize: 200, MaxSize: 800},
			{MinSize: 8000, MaxSize: 16384},  // 立即开始传输
		},
		MinRecordPayload: 30,
		MaxRecordPayload: 16384,
	}

	// TencentVideoProfile — 腾讯视频/爱奇艺长视频
	// 特征: 持续高带宽下行，非常少的上行
	// 与B站区别: 无弹幕，更纯粹的视频流
	TencentVideoProfile = &TrafficProfile{
		Name: "tencent_video",
		C2SSizes: []SizeRange{
			{Min: 26, Max: 60, Weight: 45},      // 播放器心跳、缓冲状态
			{Min: 61, Max: 200, Weight: 25},      // 清晰度切换、广告跳过
			{Min: 201, Max: 600, Weight: 15},     // DRM 许可请求、选集
			{Min: 601, Max: 1500, Weight: 10},    // 播放历史上报
			{Min: 1501, Max: 4000, Weight: 5},    // 评论提交
		},
		S2CSizes: []SizeRange{
			{Min: 26, Max: 100, Weight: 3},        // ACK
			{Min: 101, Max: 500, Weight: 3},       // 播放信息
			{Min: 501, Max: 3000, Weight: 4},      // 字幕、播放列表
			{Min: 3001, Max: 10000, Weight: 15},   // 中等视频分片
			{Min: 10001, Max: 16384, Weight: 75},  // ★★★ 视频流(绝对主导)
		},
		C2SInitial: []InitialPacket{
			{MinSize: 60, MaxSize: 100},
			{MinSize: 26, MaxSize: 40},
			{MinSize: 150, MaxSize: 500},   // 播放请求
			{MinSize: 26, MaxSize: 60},
		},
		S2CInitial: []InitialPacket{
			{MinSize: 80, MaxSize: 180},
			{MinSize: 26, MaxSize: 40},
			{MinSize: 500, MaxSize: 2000},     // 播放配置
			{MinSize: 12000, MaxSize: 16384},  // 首帧视频数据
		},
		MinRecordPayload: 26,
		MaxRecordPayload: 16384,
	}

	// profileRegistry for lookup by name
	profileRegistry = map[string]*TrafficProfile{
		"chrome_h2":       ChromeH2Profile,
		"safari":          SafariProfile,
		"firefox":         FirefoxProfile,
		"douyin":          DouyinProfile,
		"bilibili":        BilibiliProfile,
		"apple_music":     AppleMusicProfile,
		"taobao":          TaobaoProfile,
		"icloud_sync":     ICloudSyncProfile,
		"tencent_video":   TencentVideoProfile,
	}
	registryMu sync.RWMutex
)

// GetProfile returns a profile by name, defaulting to ChromeH2.
func GetProfile(name string) *TrafficProfile {
	registryMu.RLock()
	defer registryMu.RUnlock()
	if p, ok := profileRegistry[name]; ok {
		return p
	}
	return ChromeH2Profile
}

// GetRandomProfile returns a randomly selected profile.
func GetRandomProfile() *TrafficProfile {
	registryMu.RLock()
	defer registryMu.RUnlock()
	profiles := make([]*TrafficProfile, 0, len(profileRegistry))
	for _, p := range profileRegistry {
		profiles = append(profiles, p)
	}
	return profiles[rand.Intn(len(profiles))]
}

// SampleSize picks a random size from the given distribution.
func SampleSize(ranges []SizeRange) int {
	totalWeight := 0
	for _, r := range ranges {
		totalWeight += r.Weight
	}
	if totalWeight == 0 {
		return 512
	}
	pick := rand.Intn(totalWeight)
	cumulative := 0
	for _, r := range ranges {
		cumulative += r.Weight
		if pick < cumulative {
			if r.Min == r.Max {
				return r.Min
			}
			return r.Min + rand.Intn(r.Max-r.Min+1)
		}
	}
	// fallback
	last := ranges[len(ranges)-1]
	return last.Min + rand.Intn(last.Max-last.Min+1)
}

// SampleInitialSize picks a size for a specific position in the initial sequence.
func SampleInitialSize(initial []InitialPacket, index int) int {
	if index >= len(initial) {
		return -1 // no more initial packets, use normal distribution
	}
	p := initial[index]
	if p.MinSize == p.MaxSize {
		return p.MinSize
	}
	return p.MinSize + rand.Intn(p.MaxSize-p.MinSize+1)
}
