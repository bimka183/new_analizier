package repository

import (
	"analizier/backend/src/models"
	"fmt"
	"strings"

	"gorm.io/gorm"
)

type TrafficRepository interface {
	Create(traffic *models.Traffic) error
	CreateBulk(traffics []*models.Traffic) error
	GetTraffic(limit int, offset int) ([]models.Traffic, error)
	GetTrafficByID(id uint) (*models.Traffic, error)
	GetTrafficWithFilter(limit int, offset int, filter models.TrafficFilter) ([]models.Traffic, error)
	CountTraffic(filter models.TrafficFilter) (int64, error)
	WriteFlowAnomaly() error
	// Методы для администрирования
	DeleteAllTraffic() error
	ResetDatabase() error
	// Методы для пользователей
	CreateUser(user *models.User) error
	GetUserByUsername(username string) (*models.User, error)
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

func (r *postgresTrafficRepo) GetTrafficByID(id uint) (*models.Traffic, error) {
	var traffic models.Traffic
	tx := r.db.Preload("Anomalies").First(&traffic, id)
	if tx.Error != nil {
		return nil, tx.Error
	}
	return &traffic, nil
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

// applyFilters applies TrafficFilter conditions to a GORM query
func (r *postgresTrafficRepo) applyFilters(query *gorm.DB, filter models.TrafficFilter) *gorm.DB {
	if filter.SourceIP != "" {
		query = query.Where("source_ip LIKE ?", "%"+filter.SourceIP+"%")
	}
	if filter.DestinationIP != "" {
		query = query.Where("destination_ip LIKE ?", "%"+filter.DestinationIP+"%")
	}
	if filter.Port != "" {
		query = query.Where("source_port = ? OR destination_port = ?", filter.Port, filter.Port)
	}
	if filter.Protocol != "" {
		query = query.Where("protocol = ?", filter.Protocol)
	}
	if filter.AnomalyType != "" {
		if filter.AnomalyType == "None" {
			// Записи без аномалий
			query = query.Where("id NOT IN (SELECT traffic_id FROM anomalies)")
		} else {
			query = query.Where("id IN (SELECT traffic_id FROM anomalies WHERE anomaly_type = ?)", filter.AnomalyType)
		}
	}
	return query
}

func (r *postgresTrafficRepo) GetTrafficWithFilter(limit int, offset int, filter models.TrafficFilter) ([]models.Traffic, error) {
	var traffic []models.Traffic
	query := r.db.Model(&models.Traffic{}).
		Preload("Anomalies")

	query = r.applyFilters(query, filter)

	tx := query.Order("id DESC").Limit(limit).Offset(offset).Find(&traffic)
	if tx.Error != nil {
		return nil, tx.Error
	}
	return traffic, nil
}

func (r *postgresTrafficRepo) WriteFlowAnomaly() error {
	return fmt.Errorf("not implemented")
}

func (r *postgresTrafficRepo) CountTraffic(filter models.TrafficFilter) (int64, error) {
	var count int64
	query := r.db.Model(&models.Traffic{})
	query = r.applyFilters(query, filter)
	tx := query.Count(&count)
	if tx.Error != nil {
		return 0, tx.Error
	}
	return count, nil
}

// DeleteAllTraffic удаляет все записи трафика и аномалий (очистка БД)
func (r *postgresTrafficRepo) DeleteAllTraffic() error {
	// Сначала удаляем все аномалии
	if err := r.db.Exec("DELETE FROM anomalies").Error; err != nil {
		return err
	}
	// Затем удаляем весь трафик
	if err := r.db.Exec("DELETE FROM traffics").Error; err != nil {
		return err
	}
	return nil
}

// ResetDatabase удаляет все данные и пересоздаёт таблицы (откат до базовых настроек)
func (r *postgresTrafficRepo) ResetDatabase() error {
	// Удаляем таблицы
	if err := r.db.Migrator().DropTable(&models.Anomaly{}); err != nil {
		return err
	}
	if err := r.db.Migrator().DropTable(&models.Traffic{}); err != nil {
		return err
	}
	if err := r.db.Migrator().DropTable(&models.Upload{}); err != nil {
		return err
	}
	// Пересоздаём таблицы
	if err := r.db.AutoMigrate(&models.Traffic{}, &models.Anomaly{}); err != nil {
		return err
	}
	return nil
}

// CreateUser создаёт нового пользователя
func (r *postgresTrafficRepo) CreateUser(user *models.User) error {
	return r.db.Create(user).Error
}

// GetUserByUsername ищет пользователя по имени
func (r *postgresTrafficRepo) GetUserByUsername(username string) (*models.User, error) {
	var user models.User
	tx := r.db.Where("username = ?", username).First(&user)
	if tx.Error != nil {
		return nil, tx.Error
	}
	return &user, nil
}
