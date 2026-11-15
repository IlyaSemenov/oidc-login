import { expect, test } from "bun:test"

import { isSecureIssuerUrl } from "./issuer-url"

test("accepts HTTPS issuers", () => {
  expect(isSecureIssuerUrl("https://accounts.example.com")).toBe(true)
})

test("accepts plain HTTP only on loopback hosts", () => {
  expect(isSecureIssuerUrl("http://localhost:8080")).toBe(true)
  expect(isSecureIssuerUrl("http://app.localhost")).toBe(true)
  expect(isSecureIssuerUrl("http://127.0.0.1")).toBe(true)
  expect(isSecureIssuerUrl("http://[::1]:8080")).toBe(true)
  expect(isSecureIssuerUrl("http://example.com")).toBe(false)
  expect(isSecureIssuerUrl("http://localhost.example.com")).toBe(false)
})

test("rejects invalid URLs", () => {
  expect(isSecureIssuerUrl("accounts.example.com")).toBe(false)
})
