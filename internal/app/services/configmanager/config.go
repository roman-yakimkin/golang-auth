package configmanager

import (
	"github.com/go-yaml/yaml"
	"os"
)

type Config struct {
	BindAddr                string `yaml:"bind_addr"`
	JWTSecretKey            string `yaml:"jwt_secret_key"`
	JWTAccessTokenLifeTime  int    `yaml:"jwt_access_token_life_time"`
	JWTRefreshTokenLifeTime int    `yaml:"jwt_refresh_token_life_time"`

	MongoDBConnStr string `yaml:"mongodb_connection_string"`

	Roles []map[string]interface{} `yaml:"roles"`
	Users []map[string]interface{} `yaml:"users"`
}

func NewConfig() *Config {
	return &Config{
		BindAddr: ":8080",
	}
}

func (cm *Config) Init(configPath string) error {
	yamlFile, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(yamlFile, cm)
	return err
}
