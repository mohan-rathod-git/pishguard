/** @type {import('next').NextConfig} */
const nextConfig = {
  // Allow @/ path alias
  experimental: {},
  // Suppress styled-jsx warning (we use Tailwind now)
  compiler: {},
  images: {
    remotePatterns: [],
  },
};

export default nextConfig;
