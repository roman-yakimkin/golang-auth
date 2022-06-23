package interfaces

type PasswordManager interface {
	EncodePassword(password string) (string, error)
	ComparePasswords(hashedPsw string, plainPwd string) bool
}
