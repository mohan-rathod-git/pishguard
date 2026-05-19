/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    // Treat these native modules as external so Next.js doesn't try to bundle them
    serverComponentsExternalPackages: ['sharp', 'jsqr'],
  },
  compiler: {},
  images: {
    remotePatterns: [],
  },
};

export default nextConfig;
