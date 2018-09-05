
# Usage

Install ansible beforehand. Then run:

```
     ansible-playbook -i "localhost," --connection=local installnginx.yml
```

# Customization

Please change `$ngo_*` parameters accordingly in `nginx.conf`
Also please modify the `location` directive for your use case.

