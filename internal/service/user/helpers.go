package user

import (
	"fmt"
	"forum/internal/entity"
	"forum/internal/validator"
	"regexp"
)

const (
	maxUsernameLen = 255
	maxEmailLen    = 255
	minPasswordLen = 8
	maxPasswordLen = 500
)

var EmailRX = regexp.MustCompile(`(?i)(?:[a-z0-9!#$%&'*+\/=?^_\x60{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_\x60{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])`)

func IsRightSignUp(u *entity.UserSignupForm) bool {
	u.CheckField(validator.NotBlank(u.Username), "username", "This field cannot be blank")
	u.CheckField(validator.MaxChar(u.Username, maxUsernameLen), "username", fmt.Sprintf("Maximum characters length exceeded - %d", maxUsernameLen))
	u.CheckField(validator.ValidString(u.Username), "username", "Only valid characters (ascii standard) should be included")
	u.CheckField(validator.NotBlank(u.Email), "email", "This field cannot be blank")
	u.CheckField(validator.MaxChar(u.Email, maxEmailLen), "email", fmt.Sprintf("Maximum characters length exceeded - %d", maxEmailLen))
	u.CheckField(validator.Matches(u.Email, EmailRX), "email", "Invalid email address")
	u.CheckField(validator.ValidString(u.Email), "email", "Only valid characters (ascii standard) should be included")
	u.CheckField(validator.NotBlank(u.Password), "password", "This field cannot be blank")
	u.CheckField(validator.MinChar(u.Password, minPasswordLen), "password", fmt.Sprintf("Minimum length for password: %d", minPasswordLen))
	u.CheckField(validator.MaxChar(u.Password, maxPasswordLen), "password", fmt.Sprintf("Maximum characters length exceeded - %d", maxPasswordLen))
	u.CheckField(validator.ValidString(u.Password), "password", "Only valid characters (ascii standard) should be included")

	return u.Valid()
}

func IsRightLogin(u *entity.UserLoginForm) bool {
	u.CheckField(validator.NotBlank(u.Identifier), "identifier", "This field cannot be blank")
	u.CheckField(validator.NotBlank(u.Password), "password", "This field cannot be blank")

	return u.Valid()
}
