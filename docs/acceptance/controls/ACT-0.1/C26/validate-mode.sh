case "$MODE" in
  build|scan|target|record) ;;
  *)
    echo "::error::gatekeeper: unknown mode '$MODE' (expected build, scan, target, or record)"
    exit 1
    ;;
esac

