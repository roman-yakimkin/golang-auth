package interfaces

type Store interface {
	User() UserRepo
	Role() RoleRepo
	ExpiredRT() ExpiredRefreshTokenRepo
}
