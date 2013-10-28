{
    "servers": [
        {
            "admin_pass": "%(password)s",
            "id": "%(id)s",
            "links": [
                {
                    "href": "http://openstack.example.com/v3/servers/%(uuid)s",
                    "rel": "self"
                },
                {
                    "href": "http://openstack.example.com/servers/%(uuid)s",
                    "rel": "bookmark"
                }
            ],
            "os-disk-config:disk_config": "AUTO",
            "security_groups": [
                {
                    "name": "default"
                }
            ]
        }
    ]
}
