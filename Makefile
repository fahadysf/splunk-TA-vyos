.PHONY: test package clean

APP_NAME := TA-vyos
VERSION := 0.1.0

test:
	python3 -m unittest discover -s tests

package: clean test
	mkdir -p dist
	mkdir -p dist/$(APP_NAME)
	rsync -a --exclude='.git' --exclude='dist' --exclude='__pycache__' --exclude='*.pyc' ./ dist/$(APP_NAME)/
	tar -czf dist/$(APP_NAME)-$(VERSION).tgz -C dist $(APP_NAME)

clean:
	rm -rf dist
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	find . -name '*.pyc' -delete
