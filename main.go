// test for dig
package main

import (
	"test_for_dig/models"
)

func main() {
	ns := []string{"a.gtld-servers.net.", "b.gtld-servers.net.", "c.gtld-servers.net.", "d.gtld-servers.net.", "e.gtld-servers.net.", "f.gtld-servers.net.", "g.gtld-servers.net."}

	_ = models.Dig("3331.com", ns)

}
