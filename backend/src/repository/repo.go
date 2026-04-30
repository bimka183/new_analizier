package repository

import (
	"analizier/backend/src/models"
	"fmt"

	"gorm.io/gorm"
)

type TrafficRepository interface {
	Create(traffic *models.Traffic) error
	CreateBulk(traffics []*models.Traffic) error
	GetTraffic(limit int, offset int) ([]models.Traffic, error)
	GetTrafficWithFilter(limit int, offset int, sourceIP string) ([]models.Traffic, error)
	CountTraffic(sourceIP string) (int64, error)
	WriteFlowAnomaly() error
}

type postgresTrafficRepo struct {
	db *gorm.DB
}

func NewPostgresTrafficRepo(db *gorm.DB) TrafficRepository {
	return &postgresTrafficRepo{db: db}
}

func (r *postgresTrafficRepo) Create(traffic *models.Traffic) error {

	tx := r.db.Create(traffic)
	if tx.Error != nil {
		return tx.Error
	}
	return nil
}

func (r *postgresTrafficRepo) CreateBulk(traffics []*models.Traffic) error {
	tx := r.db.Create(traffics)
	if tx.Error != nil {
		return tx.Error
	}
	return nil
}

func (r *postgresTrafficRepo) GetTraffic(limit int, offset int) ([]models.Traffic, error) {
	var traffic []models.Traffic
	tx := r.db.Model(&models.Traffic{}).
		Select("*").
		Joins("left join anomalies on traffic.id = anomalies.traffic_id").
		Limit(limit).
		Offset(offset).
		Find(&traffic)
	if tx.Error != nil {
		return nil, tx.Error
	}
	return traffic, nil
}

func (r *postgresTrafficRepo) GetTrafficWithFilter(limit int, offset int, sourceIP string) ([]models.Traffic, error) {
	var traffic []models.Traffic
	query := r.db.Model(&models.Traffic{}).
		Preload("Anomalies")

	if sourceIP != "" {
		query = query.Where("source_ip LIKE ? OR destination_ip LIKE ?", "%"+sourceIP+"%", "%"+sourceIP+"%")
	}

	tx := query.Limit(limit).Offset(offset).Find(&traffic)
	if tx.Error != nil {
		return nil, tx.Error
	}
	return traffic, nil
}

func (r *postgresTrafficRepo) WriteFlowAnomaly() error {
	return fmt.Errorf("not implemented")
}

func (r *postgresTrafficRepo) CountTraffic(sourceIP string) (int64, error) {
	var count int64
	query := r.db.Model(&models.Traffic{})
	if sourceIP != "" {
		query = query.Where("source_ip LIKE ? OR destination_ip LIKE ?", "%"+sourceIP+"%", "%"+sourceIP+"%")
	}
	tx := query.Count(&count)
	if tx.Error != nil {
		return 0, tx.Error
	}
	return count, nil
}
