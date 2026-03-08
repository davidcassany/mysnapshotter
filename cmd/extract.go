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

	"github.com/davidcassany/ocistore/pkg/extractor"
	"github.com/spf13/cobra"
)

func initExtractorLogger(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()
	llvl, _ := flags.GetString("loglevel")
	debug, _ := flags.GetBool("debug")
	log = initLogger(debug, llvl)
	return nil
}

// pullCmd represents the pull command
var extractCmd = &cobra.Command{
	Use:     "extract IMAGE_REF DESTINATION",
	Short:   "pulls a remote image and extracts its flattened root tree to destination folder",
	Args:    cobra.ExactArgs(2),
	PreRunE: initExtractorLogger,
	RunE: func(cmd *cobra.Command, args []string) error {
		ref := args[0]
		dst := args[1]

		extract := extractor.NewExtractor(context.Background(), log)
		_, err := extract.ExtractImage(ref, dst, "", false, false)
		return err
	},
}

func init() {
	rootCmd.AddCommand(extractCmd)
}
