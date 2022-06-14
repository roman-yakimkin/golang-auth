package passwordmanager

import "golang.org/x/crypto/bcrypt"

type BCryptPasswordManager struct {
}

func (pm *BCryptPasswordManager) EncodePassword(password string) (string, error) {
	encoded, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(encoded), err
}

func (pm *BCryptPasswordManager) ComparePasswords(hashedPsw string, plainPwd string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPsw), []byte(plainPwd))
	return err == nil
}
