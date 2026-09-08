package geodata

import (
	"fmt"
	"strings"

	"github.com/metacubex/mihomo/common/singleflight"
	"github.com/metacubex/mihomo/component/geodata/router"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/oschwald/maxminddb-golang"
	"google.golang.org/protobuf/proto"
)

var (
	geoMode        bool
	geoLoaderName  = "memconservative"
	geoSiteMatcher = "succinct"
)

//  geoLoaderName = "standard"

func GeodataMode() bool {
	return geoMode
}

func LoaderName() string {
	return geoLoaderName
}

func SiteMatcherName() string {
	return geoSiteMatcher
}

func SetGeodataMode(newGeodataMode bool) {
	geoMode = newGeodataMode
}

func SetLoader(newLoader string) {
	if newLoader == "memc" {
		newLoader = "memconservative"
	}
	geoLoaderName = newLoader
}

func SetSiteMatcher(newMatcher string) {
	switch newMatcher {
	case "mph", "hybrid":
		geoSiteMatcher = "mph"
	default:
		geoSiteMatcher = "succinct"
	}
}

func VerifyMMDBBytes(data []byte) error {
	reader, err := maxminddb.FromBytes(data)
	if err != nil {
		return err
	}
	defer reader.Close()
	// Verify() additionally rejects readable databases with optional metadata
	// omitted. Validate the actual index and records without that restriction.
	networks := reader.Networks(maxminddb.SkipAliasedNetworks)
	count := 0
	for networks.Next() {
		var record any
		if _, err := networks.Network(&record); err != nil {
			return err
		}
		count++
	}
	if err := networks.Err(); err != nil {
		return err
	}
	if count == 0 {
		return fmt.Errorf("empty MMDB database")
	}
	return nil
}

// VerifyGeoIPBytes and VerifyGeoSiteBytes decode every record before a
// downloaded candidate wins; valid outer framing alone is not enough.
func VerifyGeoIPBytes(data []byte) error {
	var database router.GeoIPList
	if err := proto.Unmarshal(data, &database); err != nil {
		return err
	}
	if len(database.Entry) == 0 {
		return fmt.Errorf("empty GeoIP database")
	}
	for _, entry := range database.Entry {
		if entry.CountryCode == "" {
			return fmt.Errorf("GeoIP entry has no country code")
		}
		for _, cidr := range entry.Cidr {
			if len(cidr.Ip) != 4 && len(cidr.Ip) != 16 || cidr.Prefix > uint32(len(cidr.Ip)*8) {
				return fmt.Errorf("invalid GeoIP CIDR")
			}
		}
	}
	return nil
}

func VerifyGeoSiteBytes(data []byte) error {
	var database router.GeoSiteList
	if err := proto.Unmarshal(data, &database); err != nil {
		return err
	}
	if len(database.Entry) == 0 {
		return fmt.Errorf("empty GeoSite database")
	}
	for _, entry := range database.Entry {
		if entry.CountryCode == "" {
			return fmt.Errorf("GeoSite entry has no country code")
		}
		for _, domain := range entry.Domain {
			if domain.Type < router.Domain_Plain || domain.Type > router.Domain_Full {
				return fmt.Errorf("invalid GeoSite domain type")
			}
		}
	}
	return nil
}

func Verify(name string) error {
	switch name {
	case C.GeositeName:
		_, err := LoadGeoSiteMatcher("CN")
		return err
	case C.GeoipName:
		_, err := LoadGeoIPMatcher("CN")
		return err
	default:
		return fmt.Errorf("not support name")
	}
}

var loadGeoSiteMatcherListSF = singleflight.Group[[]*router.Domain]{StoreResult: true}
var loadGeoSiteMatcherSF = singleflight.Group[router.DomainMatcher]{StoreResult: true}

func LoadGeoSiteMatcher(countryCode string) (router.DomainMatcher, error) {
	if countryCode == "" {
		return nil, fmt.Errorf("country code could not be empty")
	}

	not := false
	if countryCode[0] == '!' {
		not = true
		countryCode = countryCode[1:]
		if countryCode == "" {
			return nil, fmt.Errorf("country code could not be empty")
		}
	}
	countryCode = strings.ToLower(countryCode)

	parts := strings.Split(countryCode, "@")
	listName := strings.TrimSpace(parts[0])
	attrVal := parts[1:]
	attrs := parseAttrs(attrVal)

	if listName == "" {
		return nil, fmt.Errorf("empty listname in rule: %s", countryCode)
	}

	matcherName := listName
	if !attrs.IsEmpty() {
		matcherName += "@" + attrs.String()
	}
	matcher, err, shared := loadGeoSiteMatcherSF.Do(matcherName, func() (router.DomainMatcher, error) {
		log.Infoln("Load GeoSite rule: %s", matcherName)
		domains, err, shared := loadGeoSiteMatcherListSF.Do(listName, func() ([]*router.Domain, error) {
			geoLoader, err := GetGeoDataLoader(geoLoaderName)
			if err != nil {
				return nil, err
			}
			return geoLoader.LoadGeoSite(listName)
		})
		if err != nil {
			if !shared {
				loadGeoSiteMatcherListSF.Forget(listName) // don't store the error result
			}
			return nil, err
		}

		if attrs.IsEmpty() {
			if strings.Contains(countryCode, "@") {
				log.Warnln("empty attribute list: %s", countryCode)
			}
		} else {
			filteredDomains := make([]*router.Domain, 0, len(domains))
			hasAttrMatched := false
			for _, domain := range domains {
				if attrs.Match(domain) {
					hasAttrMatched = true
					filteredDomains = append(filteredDomains, domain)
				}
			}
			if !hasAttrMatched {
				log.Warnln("attribute match no rule: geosite: %s", countryCode)
			}
			domains = filteredDomains
		}

		/**
		linear: linear algorithm
		matcher, err := router.NewDomainMatcher(domains)
		mph：minimal perfect hash algorithm
		*/
		if geoSiteMatcher == "mph" {
			return router.NewMphMatcherGroup(domains)
		} else {
			return router.NewSuccinctMatcherGroup(domains)
		}
	})
	if err != nil {
		if !shared {
			loadGeoSiteMatcherSF.Forget(matcherName) // don't store the error result
		}
		return nil, err
	}
	if not {
		matcher = router.NewNotDomainMatcherGroup(matcher)
	}

	return matcher, nil
}

var loadGeoIPMatcherSF = singleflight.Group[router.IPMatcher]{StoreResult: true}

func LoadGeoIPMatcher(country string) (router.IPMatcher, error) {
	if len(country) == 0 {
		return nil, fmt.Errorf("country code could not be empty")
	}

	not := false
	if country[0] == '!' {
		not = true
		country = country[1:]
	}
	country = strings.ToLower(country)

	matcher, err, shared := loadGeoIPMatcherSF.Do(country, func() (router.IPMatcher, error) {
		log.Infoln("Load GeoIP rule: %s", country)
		geoLoader, err := GetGeoDataLoader(geoLoaderName)
		if err != nil {
			return nil, err
		}
		cidrList, err := geoLoader.LoadGeoIP(country)
		if err != nil {
			return nil, err
		}
		return router.NewGeoIPMatcher(cidrList)
	})
	if err != nil {
		if !shared {
			loadGeoIPMatcherSF.Forget(country) // don't store the error result
			log.Warnln("Load GeoIP rule: %s", country)
		}
		return nil, err
	}
	if not {
		matcher = router.NewNotIpMatcherGroup(matcher)
	}
	return matcher, nil
}

func ClearGeoSiteCache() {
	loadGeoSiteMatcherListSF.Reset()
	loadGeoSiteMatcherSF.Reset()
}

func ClearGeoIPCache() {
	loadGeoIPMatcherSF.Reset()
}
