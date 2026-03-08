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
	"github.com/spf13/cobra"
)

// unpackCmd represents the unpack command
var unpackCmd = &cobra.Command{
	Use:     "unpack IMAGE_NAME",
	Short:   "Unpacks the given image",
	Args:    cobra.ExactArgs(1),
	PreRunE: initCS,
	RunE: func(cmd *cobra.Command, args []string) error {
		log := cs.Logger()

		log.Infof("Attempting to unpack %q", args[0])
		err := cs.Unpack(args[0])
		if err != nil {
			return err
		}
		log.Info("Unpack done")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(unpackCmd)
}
