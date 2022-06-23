package interfaces

type ExpiredRefreshTokenRepo interface {
	MemorizeIfExpired(string) error
	IsExpired(string) (bool, error)
	Clean() error
}
