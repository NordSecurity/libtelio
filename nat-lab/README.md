# NAT lab

NAT lab is an environment where libtelio is tested.
We are working on making it locally runnable for everyone outside of
Nord Security organization, but currently it is only possible to run
them in the CI.

## Formatting

Python code is formatted using https://github.com/psf/black, https://github.com/PyCQA/isort and https://github.com/PyCQA/autoflake.
Unformatted code will automatically be declined by the CI.
```
black . && isort . && autoflake .
```

## Linter and typecheck

Python code is checked using https://github.com/python/mypy and https://github.com/pylint-dev/pylint.
Any faulty code will automatically be declined by the CI.
```
mypy . && pylint .
```

## Dependency lock / upgrade
All dependencies and transitive dependencies should be locked to prevent breaking things. Also has to be updated from time to time, to keep things fresh.

#### How to lock
```
$ pipenv lock
```

#### How to upgrade
```
$ pipenv upgrade <package>
```