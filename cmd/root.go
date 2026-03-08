/*
Copyright © 2024 SUSE LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"context"
	"os"

	"github.com/davidcassany/ocistore/pkg/logger"
	"github.com/davidcassany/ocistore/pkg/ocistore"
	"github.com/spf13/cobra"
)

var cs *ocistore.OCIStore
var log logger.Logger

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "ocistore",
	Short: "A daememon less client for a local image containerd store",
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func initLogger(debug bool, llvl string) logger.Logger {
	var log logger.Logger
	var err error

	if debug {
		log, _ = logger.NewLogger(logger.DebugLevel)
	} else if llvl != "" {
		log, err = logger.NewLogger(llvl)
		if err != nil {
			log, _ = logger.NewLogger(logger.DebugLevel)
		}
		log.Warnf("could parse log level '%s', setting log to '%s' level", llvl, logger.DebugLevel)
	} else {
		log, _ = logger.NewLogger(logger.InfoLevel)
	}
	return log
}

func initCS(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()
	root, _ := flags.GetString("root")
	llvl, _ := flags.GetString("loglevel")
	debug, _ := flags.GetBool("debug")

	log = initLogger(debug, llvl)

	cs = ocistore.NewOCIStore(log, root)
	return cs.Init(context.Background())
}

func init() {
	rootCmd.PersistentFlags().String("root", ocistore.DefaultRoot, "path for the containerd local store")
	rootCmd.PersistentFlags().Bool("debug", false, "set log ouput to debug level")
	rootCmd.PersistentFlags().String("loglevel", "", "set log ouput level")
	rootCmd.MarkFlagsMutuallyExclusive("debug", "loglevel")

	cobra.OnFinalize(
		func() {
			if cs != nil && cs.IsInitiated() {
				err := cs.GetSnapshotter(cs.GetDriver()).Close()
				if err != nil {
					cs.Logger().Warnf("failed closing snapshotter: %v", err)
				}
			}
		}, func() {
			if cs != nil && cs.IsInitiated() {
				err := cs.RunGarbageCollector()
				if err != nil {
					cs.Logger().Warnf("failed running garbage collector: %v", err)
				}
			}
		},
	)
}
