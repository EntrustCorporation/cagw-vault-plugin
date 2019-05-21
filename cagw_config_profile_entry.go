/*
 * Copyright (c) 2019 Entrust Datacard Corporation.
 * All rights reserved.
 */

package main

import "time"

type CAGWConfigProfileEntry struct {
	/*
		The name of the subject variable to use for the common_name. By
		default this is a variable named 'cn'.
	*/
	CommonNameVariable string        `json:"common_name_variable" mapstructure:"common_name_variable"`
	TTL                time.Duration `json:"ttl_duration" mapstructure:"ttl_duration"`
	MaxTTL             time.Duration `json:"max_ttl_duration" mapstructure:"max_ttl_duration"`
}
