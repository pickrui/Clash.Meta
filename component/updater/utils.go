package updater

import (
	"context"
	"time"

	mihomoHttp "github.com/metacubex/mihomo/component/http"

	"github.com/metacubex/http"
)

const defaultHttpTimeout = time.Second * 90

func downloadForBytes(url string, validators ...func([]byte) error) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultHttpTimeout)
	defer cancel()
	_, data, err := mihomoHttp.Get(ctx, url, nil, 0, func(_ *http.Response, data []byte) error {
		for _, validate := range validators {
			if err := validate(data); err != nil {
				return err
			}
		}
		return nil
	}, mihomoHttp.WithPublicRead())
	return data, err
}
