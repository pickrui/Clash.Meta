package updater

import (
	"context"
	"time"

	"github.com/metacubex/mihomo/log"
)

var (
	GeoUpdateHook func(geoType string, updating bool, skipped bool, updateErr error)
)

func sendGeoUpdateStatus(geoType string, updating bool, skipped bool, updateErr error) {
	if GeoUpdateHook != nil {
		GeoUpdateHook(geoType, updating, skipped, updateErr)
	}
}

var geoUpdateCancel context.CancelFunc

func RegisterGeoUpdaterWithCancel() {
	if geoUpdateCancel != nil {
		geoUpdateCancel()
	}

	if updateInterval <= 0 {
		log.Errorln("[GEO] Invalid update interval: %d", updateInterval)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	geoUpdateCancel = cancel

	go func() {
		ticker := time.NewTicker(time.Duration(updateInterval) * time.Hour)
		defer ticker.Stop()

		lastUpdate, err := getUpdateTime()
		if err != nil {
			log.Errorln("[GEO] Get GEO database update time error: %s", err.Error())
			return
		}

		log.Infoln("[GEO] last update time %s", lastUpdate)
		if lastUpdate.Add(time.Duration(updateInterval) * time.Hour).Before(time.Now()) {
			log.Infoln("[GEO] Database has not been updated for %v, update now", time.Duration(updateInterval)*time.Hour)
			if err := UpdateGeoDatabases(); err != nil {
				log.Errorln("[GEO] Failed to update GEO database: %s", err.Error())
				return
			}
		}

		for {
			select {
			case <-ctx.Done():
				log.Infoln("[GEO] Geo updater stopped")
				return
			case <-ticker.C:
				log.Infoln("[GEO] updating database every %d hours", updateInterval)
				if err := UpdateGeoDatabases(); err != nil {
					log.Errorln("[GEO] Failed to update GEO database: %s", err.Error())
				}
			}
		}
	}()
}
