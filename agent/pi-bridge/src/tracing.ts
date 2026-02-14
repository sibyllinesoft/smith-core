/**
 * OpenTelemetry tracing setup for pi-bridge.
 *
 * Must be imported before any other modules to ensure
 * the SDK is initialized before spans are created.
 *
 * Exports spans to the OTel Collector via gRPC (OTLP).
 */

import { NodeSDK } from "@opentelemetry/sdk-node";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-grpc";
import { Resource } from "@opentelemetry/resources";
import { ATTR_SERVICE_NAME } from "@opentelemetry/semantic-conventions";

const sdk = new NodeSDK({
  resource: new Resource({
    [ATTR_SERVICE_NAME]: "pi-bridge",
  }),
  traceExporter: new OTLPTraceExporter({
    url: process.env.OTEL_EXPORTER_OTLP_ENDPOINT ?? "http://otel-collector:4317",
  }),
});

sdk.start();

process.on("SIGTERM", () => {
  sdk.shutdown().catch(console.error);
});
