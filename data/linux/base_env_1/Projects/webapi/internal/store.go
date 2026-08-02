package internal

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(databaseURL string) (*Store, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}

	config.MaxConns = 20
	config.MinConns = 5
	config.MaxConnLifetime = 30 * time.Minute
	config.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}

	if err := pool.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return &Store{pool: pool}, nil
}

func (s *Store) Close() {
	s.pool.Close()
}

type Pipeline struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Schedule    string     `json:"schedule"`
	OwnerTeam   string     `json:"owner_team"`
	Status      string     `json:"status"`
	LastRunAt   *time.Time `json:"last_run_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

func (s *Store) ListPipelines(ctx context.Context) ([]Pipeline, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, description, schedule, owner_team, status, last_run_at, created_at, updated_at
		FROM pipelines
		WHERE status = 'active'
		ORDER BY updated_at DESC
		LIMIT 100
	`)
	if err != nil {
		return nil, fmt.Errorf("query pipelines: %w", err)
	}
	defer rows.Close()

	var pipelines []Pipeline
	for rows.Next() {
		var p Pipeline
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Schedule, &p.OwnerTeam, &p.Status, &p.LastRunAt, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan pipeline: %w", err)
		}
		pipelines = append(pipelines, p)
	}

	return pipelines, rows.Err()
}

func (s *Store) GetPipeline(ctx context.Context, id string) (*Pipeline, error) {
	var p Pipeline
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, description, schedule, owner_team, status, last_run_at, created_at, updated_at
		FROM pipelines
		WHERE id = $1
	`, id).Scan(&p.ID, &p.Name, &p.Description, &p.Schedule, &p.OwnerTeam, &p.Status, &p.LastRunAt, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("get pipeline %s: %w", id, err)
	}
	return &p, nil
}
