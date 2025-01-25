# potentii/action-read-yaml

Use `@potentii/action-read-yaml` action to read YAML files and access the values on your workflows.


---


## Usage

Considering you need to read the following **YAML** file on your the repository:

```yaml
# configs/app-config.yaml

app:
    name: My application
    version: 1.2.0

features:
    - Feature X
    - Feature Y
    - Feature Z

deploy:
    account_id: 0123456789

```

You can use this step on your **workflow** to **access** the values:

```yaml
# .github/workflows/my-workflow.yaml

# ...

jobs:
  my-job:

  # ...

  steps:

    - name: Checkout
      uses: actions/checkout@v4



    # Reading the YAML file:
    - name: Read Configurations
      uses: Potentii/action-read-yaml@1.0.0
      id: read_yaml # The read result will be stored in this step ID
      with:
        file-path: ${{ github.workspace }}/configs/app-config.yaml # The path to your YAML file



    # Example accessing the YAML properties:
    - name: Print example 1
      run: echo ${{ steps.read_yaml.outputs['$.app.name'] }} # Will print: My application

    - name: Print example 2
      run: echo ${{ steps.read_yaml.outputs['$.features.[2]'] }} # Will print: Feature Z

```


---


## Outputs

The `read_yaml` action above will **expose** these **outputs**:

### `['$.<JSON Path>']`:

If the reading is **successful**, you can access all the **YAML keys** using **JSON Path syntax**, internally we use [`jsonpath`](https://github.com/dchester/jsonpath) package to generate these outputs.

### `['outcome']`:

This **string** output informs if the action had `'success'` or `'failure'`.

### `['error']`:

This **string** output informs the action **error message**, if it has failed.


In the above example, the resulting `steps.read_yaml.outputs` variable will have:

```text
['outcome']             -> 'success'
['error']               ->
['$.app']               -> '{"name":"My application","version":"1.2.0"}'
['$.app.name']          -> 'My application'
['$.app.version']       -> '1.2.0'
['$.features']          -> '["Feature X","Feature Y","Feature Z"]'
['$.features[0]']       -> 'Feature X'
['$.features[1]']       -> 'Feature Y'
['$.features[2]']       -> 'Feature Z'
['$.deploy']            -> '{"account_id":123456789}'
['$.deploy.account_id'] -> '123456789'
```

---

## License

[MIT](LICENSE)

