package updater

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/geodata"
	_ "github.com/metacubex/mihomo/component/geodata/standard"
	mihomoHttp "github.com/metacubex/mihomo/component/http"
	"github.com/metacubex/mihomo/component/mmdb"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"golang.org/x/sync/errgroup"
)

var (
	autoUpdate     bool
	updateInterval int

	updatingGeo atomic.Bool
)

func GeoAutoUpdate() bool {
	return autoUpdate
}

func GeoUpdateInterval() int {
	return updateInterval
}

func SetGeoAutoUpdate(newAutoUpdate bool) {
	autoUpdate = newAutoUpdate
}

func SetGeoUpdateInterval(newGeoUpdateInterval int) {
	updateInterval = newGeoUpdateInterval
}

func UpdateMMDB() (err error) {
	sendGeoUpdateStatus("MMDB", true, false, nil)
	var skipped bool
	defer func() { sendGeoUpdateStatus("MMDB", false, skipped, err) }()

	vehicle := resource.NewHTTPVehicle(geodata.MmdbUrl(), C.Path.MMDB(), "", nil, defaultHttpTimeout, 0, mihomoHttp.WithPublicRead())
	var oldHash utils.HashType
	if buf, err := os.ReadFile(vehicle.Path()); err == nil {
		oldHash = utils.MakeHash(buf)
	}
	data, hash, err := vehicle.ReadValidated(context.Background(), oldHash, geodata.VerifyMMDBBytes)
	if err != nil {
		return fmt.Errorf("can't download MMDB database file: %w", err)
	}
	if oldHash.Equal(hash) { // same hash, ignored
		skipped = true
		return nil
	}
	if len(data) == 0 {
		return fmt.Errorf("can't download MMDB database file: no data")
	}

	if err = writeGeoDatabase(vehicle.Path(), data); err != nil {
		return fmt.Errorf("can't save MMDB database file: %w", err)
	}
	mmdb.ReloadIP()
	return nil
}

func UpdateASN() (err error) {
	sendGeoUpdateStatus("ASN", true, false, nil)
	var skipped bool
	defer func() { sendGeoUpdateStatus("ASN", false, skipped, err) }()

	vehicle := resource.NewHTTPVehicle(geodata.ASNUrl(), C.Path.ASN(), "", nil, defaultHttpTimeout, 0, mihomoHttp.WithPublicRead())
	var oldHash utils.HashType
	if buf, err := os.ReadFile(vehicle.Path()); err == nil {
		oldHash = utils.MakeHash(buf)
	}
	data, hash, err := vehicle.ReadValidated(context.Background(), oldHash, geodata.VerifyMMDBBytes)
	if err != nil {
		return fmt.Errorf("can't download ASN database file: %w", err)
	}
	if oldHash.Equal(hash) { // same hash, ignored
		skipped = true
		return nil
	}
	if len(data) == 0 {
		return fmt.Errorf("can't download ASN database file: no data")
	}

	if err = writeGeoDatabase(vehicle.Path(), data); err != nil {
		return fmt.Errorf("can't save ASN database file: %w", err)
	}
	mmdb.ReloadASN()
	return nil
}

func writeGeoDatabase(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".mihomo-geo-*")
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
		_ = os.Remove(file.Name())
	}()
	if err := file.Chmod(0o644); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	// Replacing the directory entry preserves mappings held by in-flight lookups.
	return os.Rename(file.Name(), path)
}

func UpdateGeoIp() (err error) {
	sendGeoUpdateStatus("GEOIP", true, false, nil)
	var skipped bool
	defer func() { sendGeoUpdateStatus("GEOIP", false, skipped, err) }()

	geoLoader, err := geodata.GetGeoDataLoader("standard")
	if err != nil {
		return err
	}

	vehicle := resource.NewHTTPVehicle(geodata.GeoIpUrl(), C.Path.GeoIP(), "", nil, defaultHttpTimeout, 0, mihomoHttp.WithPublicRead())
	var oldHash utils.HashType
	if buf, err := os.ReadFile(vehicle.Path()); err == nil {
		oldHash = utils.MakeHash(buf)
	}
	data, hash, err := vehicle.ReadValidated(context.Background(), oldHash, func(data []byte) error {
		if err := geodata.VerifyGeoIPBytes(data); err != nil {
			return err
		}
		_, err := geoLoader.LoadIPByBytes(data, "cn")
		return err
	})
	if err != nil {
		return fmt.Errorf("can't download GeoIP database file: %w", err)
	}
	if oldHash.Equal(hash) { // same hash, ignored
		skipped = true
		return nil
	}
	if len(data) == 0 {
		return fmt.Errorf("can't download GeoIP database file: no data")
	}

	defer geodata.ClearGeoIPCache()
	if err = vehicle.Write(data); err != nil {
		return fmt.Errorf("can't save GeoIP database file: %w", err)
	}
	return nil
}

func UpdateGeoSite() (err error) {
	sendGeoUpdateStatus("GEOSITE", true, false, nil)
	var skipped bool
	defer func() { sendGeoUpdateStatus("GEOSITE", false, skipped, err) }()

	geoLoader, err := geodata.GetGeoDataLoader("standard")
	if err != nil {
		return err
	}

	vehicle := resource.NewHTTPVehicle(geodata.GeoSiteUrl(), C.Path.GeoSite(), "", nil, defaultHttpTimeout, 0, mihomoHttp.WithPublicRead())
	var oldHash utils.HashType
	if buf, err := os.ReadFile(vehicle.Path()); err == nil {
		oldHash = utils.MakeHash(buf)
	}
	data, hash, err := vehicle.ReadValidated(context.Background(), oldHash, func(data []byte) error {
		if err := geodata.VerifyGeoSiteBytes(data); err != nil {
			return err
		}
		_, err := geoLoader.LoadSiteByBytes(data, "cn")
		return err
	})
	if err != nil {
		return fmt.Errorf("can't download GeoSite database file: %w", err)
	}
	if oldHash.Equal(hash) { // same hash, ignored
		skipped = true
		return nil
	}
	if len(data) == 0 {
		return fmt.Errorf("can't download GeoSite database file: no data")
	}

	defer geodata.ClearGeoSiteCache()
	if err = vehicle.Write(data); err != nil {
		return fmt.Errorf("can't save GeoSite database file: %w", err)
	}
	return nil
}

func updateGeoDatabases() error {
	defer runtime.GC()

	b := errgroup.Group{}

	if geodata.GeoIpEnable() {
		if geodata.GeodataMode() {
			b.Go(UpdateGeoIp)
		} else {
			b.Go(UpdateMMDB)
		}
	}

	if geodata.ASNEnable() {
		b.Go(UpdateASN)
	}

	if geodata.GeoSiteEnable() {
		b.Go(UpdateGeoSite)
	}

	return b.Wait()
}

var ErrGetDatabaseUpdateSkip = errors.New("GEO database is updating, skip")

func UpdateGeoDatabases() error {
	log.Infoln("[GEO] Start updating GEO database")

	if !updatingGeo.CompareAndSwap(false, true) {
		return ErrGetDatabaseUpdateSkip
	}

	defer updatingGeo.Store(false)

	log.Infoln("[GEO] Updating GEO database")

	if err := updateGeoDatabases(); err != nil {
		log.Errorln("[GEO] update GEO database error: %s", err.Error())
		return err
	}

	return nil
}

func getUpdateTime() (time time.Time, err error) {
	filesToCheck := []string{
		C.Path.GeoIP(),
		C.Path.MMDB(),
		C.Path.ASN(),
		C.Path.GeoSite(),
	}

	for _, file := range filesToCheck {
		var fileInfo os.FileInfo
		fileInfo, err = os.Stat(file)
		if err == nil {
			return fileInfo.ModTime(), nil
		}
	}

	return
}

func RegisterGeoUpdater() {
	if updateInterval <= 0 {
		log.Errorln("[GEO] Invalid update interval: %d", updateInterval)
		return
	}

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

		for range ticker.C {
			log.Infoln("[GEO] updating database every %d hours", updateInterval)
			if err := UpdateGeoDatabases(); err != nil {
				log.Errorln("[GEO] Failed to update GEO database: %s", err.Error())
			}
		}
	}()
}
