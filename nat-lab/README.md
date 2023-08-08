# NAT lab

NAT lab is an environment where libtelio is tested.
We are working on making it locally runnable for everyone outside of
Nord Security organization, but currently it is only possible to run
them in the CI.

## Formatting

Python code is formatted using https://github.com/psf/black and https://github.com/PyCQA/isort.
Unformatted code will automatically be declined by the CI.
```
black . && isort .
```

## Linter and typecheck

Python code is checked using https://github.com/python/mypy and https://github.com/pylint-dev/pylint.
Any faulty code will automatically be declined by the CI.
```
mypy . && pylint .
```