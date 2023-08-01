# Git Commit Message Requirements

## 1. Use the body to explain why this commit exists and on a high level what was done

Good
```
Fix buffer overflow

The buffer overflow was caused by off-by-one error when copying strings.
The source string buffer includes the null terminator, while the
destination string buffer does not.
```

Bad
```
Fix buffer overflow

Add -1 to the length of bytes being copied from the source string buffer
to the destination string buffer.
```

## 2. When there is a body, its separated from subject by a blank line

Note: subject line is mandatory, body is optional

Good
```
Fix buffer overflow

The buffer overflow was caused by off-by-one error when copying strings.
The source string buffer includes the null terminator, while the
destination string buffer does not.
```

Bad
```
Fix buffer overflow
The buffer overflow was caused by off-by-one error when copying strings.
The source string buffer includes the null terminator, while the
destination string buffer does not.
```

## 3. Limit the subject line to 50 characters

Good
```
Fix buffer overflow
```

Bad
```
Fix buffer overflow that was caused by off-by-one error when copying strings
```

## 4. Capitalize the subject line

Good
```
Fix buffer overflow
```

Bad
```
fix buffer overflow
```

## 5. Do not end the subject line with a period

Good
```
Fix buffer overflow
```

Bad
```
Fix buffer overflow.
```

## 6. Use the imperative mood in the subject line

Good
```
Fix buffer overflow
```

Bad
```
Fixed buffer overflow

Fixing buffer overflow

Buffer overflow fixed
```

## 7. Wrap the body at 72 characters

Good
```
Fix buffer overflow

The buffer overflow was caused by off-by-one error when copying strings.
The source string buffer includes the null terminator, while the
destination string buffer does not.
```

Bad
```
Fix buffer overflow

The buffer overflow was caused by off-by-one error when copying strings. The source string buffer includes the null terminator, while the destination string buffer does not.
```

## Sources

- [How to write git commit messages](https://cbea.ms/git-commit/)
