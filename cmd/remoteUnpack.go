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

// rUnpackCmd represents the pull command
var rUnpackCmd = &cobra.Command{
	Use:     "runpack IMAGE_REF",
	Short:   "pulls a remote image content and unpacks it skipping to store layer blobs into the content store",
	Args:    cobra.ExactArgs(1),
	PreRunE: initCS,
	RunE: func(cmd *cobra.Command, args []string) error {
		flags := cmd.Flags()
		skipTLS, _ := flags.GetBool("skip-tls")
		return cs.RemoteUnpack(args[0], skipTLS)
	},
}

func init() {
	rootCmd.AddCommand(rUnpackCmd)

	rUnpackCmd.Flags().Bool("skip-tls", false, "skips TLS verification")
}
