FROM gcr.io/oss-fuzz-base/base-builder-rust:v1@sha256:9643b583ef5aa3d956b3c170e93ef8283878c70c6df8c99d8a70d73c5019677f
COPY . $SRC/aur-sentry
WORKDIR $SRC/aur-sentry
COPY .clusterfuzzlite/build.sh $SRC/
