# Test configuration options
# Enable all modules for comprehensive testing
filters = "chartable,dkim,spf,surbl,regexp,fuzzy_check";

# Enable DNS
dns {
  nameserver = ["8.8.8.8:53", "8.8.4.4:53"];
}
