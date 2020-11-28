# CM - Credentials Manager

The credentials manager provides a mechanism by which NGS can store or generate user JWTs for the purpose of accessing a dashboard.

The CM is configured per account basis, allowing specific owners of an account to configure the users and roles that a dashboard user would have.

A `static` (`kind: 0`)configuration doesn't generate anything. The owner of the account adds an user email to the configuration, and then submits an user JWT that will be provided to the user on federated authentication to the dashboard. Users that are not present in the configuration will not retrieve a JWT.

[any magic type with a number will be a string in the next go around]

A `generator` (`kind: 1`) specifies in the `options` a set of `roles`.
A `role` maps a seed for a signing key registered with the account JWT, that will be used to generate user JWTs on the fly for matching users. The user JWTs generated will only have the permissions assigned in the specified role.

There are 3 possible roles `owner` - `1`, `admin - 2` and `monitor - 3`.
 
The account configuration jwt looks like this:

```
{
  "jti": "RMMURZLGYXRWAFCK3RDYOWJRAKQXQZE5LHOL3BPYHJ2OUZ5TOAXQ",
  "iat": 1606589757,
  "iss": "ABEXHKWIFGEJ2BL33WN5WF7SW46466MTID2RDWHORSDMNXF23UQ5YOTO",
  "sub": "ABEXHKWIFGEJ2BL33WN5WF7SW46466MTID2RDWHORSDMNXF23UQ5YOTO",
  "type": "dashboard-account-configuration",
  "nats": {
    "kind": 1,
    "options": {
      "roles": [
        {
          "pub_permissions": [
            "dashboard.>"
          ],
          "role": 1,
          "signing_key": "SAAIIHDA3YK6IM2RNYZODWB77V7AFBQE2U6TENNAWNDGRJTWGIW3OW7CKY",
          "sub_permissions": [
            "dashboard.>"
          ]
        },
        {
          "pub_permissions": [
            "dashboard.manager.>"
          ],
          "role": 2,
          "signing_key": "SAAONMJO3MN26CB2JAN3TXQJO33LJDDHUREXMZINWHOUDG7HGLIAKZ4NEQ",
          "sub_permissions": [
            "dashboard.manager.>"
          ]
        },
        {
          "pub_permissions": [
            "dashboard.monitor.>"
          ],
          "role": 3,
          "signing_key": "SAAKC3MHI2FCFL2YXONWZVIK5RLD6LQSKP46KUMPO2XRFNX3NE7WZ4KM5M",
          "sub_permissions": [
            "dashboard.monitor.>"
          ]
        }
      ]
    },
    "users": [
      {
        "email": "a@x.y.z",
        "role": 1
      },
      {
        "email": "b@x.y.z",
        "role": 2
      }
    ]
  }
}
```

The configuration must have a type of `dashboard-account-configuration` and be issued by the main key for the account, to be valid.

The configuration is on-boarded/updated by sending the token to `cm.update.account.config`. Note that the token is wrapped in JSON. For more information, please refer to https://github.com/aricart/cm/blob/master/cm.go

`cm.go` is the entry point to all requests honored by the credentials manager.



