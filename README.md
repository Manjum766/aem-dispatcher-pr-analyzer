# AEM Dispatcher PR Checklist

A practical checklist for reviewing AEM Dispatcher changes before merging.

## Security
- Deny-first filter strategy
- Block /system and /crx paths
- Restrict selectors and extensions
- Validate headers

## Caching
- Ignore unnecessary query parameters
- Configure statfiles correctly
- Validate cache invalidation rules

## CI/CD
- Run dispatcher validation
- Execute smoke tests
- Check cache impact

## Author
Manjunath M
