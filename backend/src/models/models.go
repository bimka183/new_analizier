package models

import "time"

type Traffic struct {
	ID              uint   `json:"id" gorm:"primaryKey"`
	UploadID        *uint  `json:"upload_id" gorm:"index"` // Привязка к конкретной загрузке/анализу
	FlowID          string `json:"flow_id"`
	Timestamp       string `json:"timestamp"`
	Interface       string `json:"interface"`
	SourceIP        string `json:"source_ip"`
	DestinationIP   string `json:"destination_ip"`
	SourcePort      string `json:"source_port"`
	DestinationPort string `json:"destination_port"`
	IPVersion       string `json:"ip_version"`
	Protocol        string `json:"protocol"`
	Length          int    `json:"length"`
	TrafficVolume   int    `json:"traffic_volume"`
	Flags           string `json:"flags"`
	// FlowStats fields
	Packets          int       `json:"packets"`
	FlowLength       int       `json:"flow_length"`
	AvgPacketSize    float64   `json:"avg_packet_size"`
	StdDevPacketSize float64   `json:"std_dev_packet_size"`
	BPS              float64   `json:"bps"`
	IATms            float64   `json:"iat_ms"`
	DurationSec      float64   `json:"duration_sec"`
	CntSYN           int       `json:"cnt_syn"`
	CntACK           int       `json:"cnt_ack"`
	CntFIN           int       `json:"cnt_fin"`
	CntPSH           int       `json:"cnt_psh"`
	CntRST           int       `json:"cnt_rst"`
	CntURG           int       `json:"cnt_urg"`
	Anomalies        []Anomaly `gorm:"foreignKey:TrafficID;constraint:OnDelete:CASCADE;" json:"anomalies"`
}

type TrafficDB struct {
}

type Anomaly struct {
	ID          uint   `gorm:"primarykey" json:"id"`
	TrafficID   uint   `json:"traffic_id" gorm:"index"`
	AnomalyType string `json:"anomaly_type"`
}

// Upload model tracks PCAP file upload and analysis history
type Upload struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	Filename   string    `json:"filename"`
	UploadedAt time.Time `json:"uploaded_at"`
	FlowCount  int       `json:"flow_count"`
	Summary    string    `json:"summary"` // Хранит UploadSummary в виде JSON-строки
}

// User model for role-based access (user/admin)
type User struct {
	ID       uint   `gorm:"primaryKey" json:"id"`
	Username string `gorm:"uniqueIndex" json:"username"`
	Password string `json:"-"`
	Role     string `json:"role" gorm:"default:user"` // "user" or "admin"
}

// TrafficFilter holds all supported server-side filter parameters
type TrafficFilter struct {
	SourceIP      string
	DestinationIP string
	Port          string
	AnomalyType   string
	Protocol      string
	Flags         string
	UploadID      *uint
}
