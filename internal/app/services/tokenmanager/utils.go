package tokenmanager

import "time"

func GetExpireTime(lifeTimeInSeconds int) time.Time {
	duration := time.Duration(lifeTimeInSeconds) * time.Second
	return time.Now().Add(duration)
}
