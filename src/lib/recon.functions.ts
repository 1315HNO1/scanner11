import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

const schema = z.object({
  domain: z
    .string()
    .min(3)
    .max(253)
    .transform((v) => v.trim())
    .refine((v) => /^(https?:\/\/)?([a-z0-9-]+\.)+[a-z]{2,}/i.test(v), "Enter a valid domain, e.g. example.com"),
});

export const scanDomain = createServerFn({ method: "POST" })
  .inputValidator((input: unknown) => schema.parse(input))
  .handler(async ({ data }) => {
    const { runScan } = await import("./recon.server");
    return runScan(data.domain);
  });