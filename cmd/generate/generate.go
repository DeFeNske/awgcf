package generate

import (
	"log"

	"github.com/ViRb3/wgcf/v2/cloudflare"
	. "github.com/ViRb3/wgcf/v2/cmd/shared"
	"github.com/ViRb3/wgcf/v2/config"
	"github.com/ViRb3/wgcf/v2/wireguard"
	"github.com/cockroachdb/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var profileFile string
var awgConfigFile string

var shortMsg = "Generates an AmneziaWG profile from the current Cloudflare Warp account"

var Cmd = &cobra.Command{
	Use:   "generate [awg2|awg3|awg3.1]",
	Short: shortMsg,
	Long:  FormatMessage(shortMsg, ``),
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		RunCommandFatal(func() error {
			version := wireguard.AWG2
			if len(args) == 1 {
				switch args[0] {
				case "awg2":
					version = wireguard.AWG2
				case "awg3":
					version = wireguard.AWG3
				case "awg3.1":
					version = wireguard.AWG31
				default:
					return errors.Errorf("unknown protocol %q; use awg2, awg3 or awg3.1", args[0])
				}
			}
			return generateProfile(version)
		})
	},
}

func init() {
	Cmd.PersistentFlags().StringVarP(&profileFile, "profile", "p", "awgcf-profile.conf", "AmneziaWG profile file")
	Cmd.PersistentFlags().StringVar(&awgConfigFile, "config", "", "custom AmneziaWG JSON configuration")
}

func generateProfile(version wireguard.AmneziaVersion) error {
	if err := EnsureConfigValidAccount(); err != nil {
		return errors.WithStack(err)
	}

	ctx := CreateContext()
	thisDevice, err := cloudflare.GetSourceDevice(ctx)
	if err != nil {
		return errors.WithStack(err)
	}

	var awg *wireguard.AmneziaConfig
	if awgConfigFile != "" {
		awg, err = wireguard.LoadAmneziaConfig(awgConfigFile)
		if err != nil {
			return errors.WithStack(err)
		}
		if awg.Version != version {
			return errors.Errorf("AWG config version is %q, but command requested %q", awg.Version, version)
		}
	} else {
		awg, err = wireguard.NewRandomAmneziaConfig(version)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	profile, err := wireguard.NewProfile(&wireguard.ProfileData{
		PrivateKey: viper.GetString(config.PrivateKey),
		Address1:   thisDevice.Config.Interface.Addresses.V4,
		Address2:   thisDevice.Config.Interface.Addresses.V6,
		PublicKey:  thisDevice.Config.Peers[0].PublicKey,
		Endpoint:   thisDevice.Config.Peers[0].Endpoint.Host,
		Amnezia:    awg,
	})
	if err != nil {
		return errors.WithStack(err)
	}
	if err := profile.Save(profileFile); err != nil {
		return errors.WithStack(err)
	}

	log.Println("Successfully generated AmneziaWG profile:", profileFile)
	log.Printf("AmneziaWG version: %s", awg.Version)
	return nil
}
