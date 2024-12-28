import path from "path"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

export default defineConfig({
  plugins: [react()],
  root: path.resolve(__dirname, "./"),
  base: './',
  build: {
    outDir: path.resolve(__dirname, "build"),
    emptyOutDir: true,
    sourcemap: 'inline',
    copyPublicDir: true,
  },
  publicDir: 'public',
  resolve: {
    alias: {
      "mn.core": path.resolve(__dirname, "./app/mn.core.js"),
      "mn.app.imports": path.resolve(__dirname, "./app/mn.app.imports.js"),
      "mn.pools.service": path.resolve(__dirname, "./app/mn.pools.service.js"),
      "mn.element.crane": path.resolve(__dirname, "./app/mn.element.crane.js"),
      "mn.select.module": path.resolve(__dirname, "./app/mn.select.module.js"),
      "mn.admin.service": path.resolve(__dirname, "./app/mn.admin.service.js"),
      "mn.react.router": path.resolve(__dirname, "./app/mn.react.router.js"),
      "mn.pipes.module": path.resolve(__dirname, "./app/mn.pipes.module.js"),
      "mn.shared.module": path.resolve(__dirname, "./app/mn.shared.module.js"),
      "mn.http.interceptor": path.resolve(__dirname, "./app/mn.http.interceptor.js"),
      "mn.input.filter.module": path.resolve(__dirname, "./app/mn.input.filter.module.js"),
      "components/mn_alerts": path.resolve(__dirname, "./app/components/mn_alerts.js"),
      "components/mn_pools": path.resolve(__dirname, "./app/components/mn_pools.js"),
      "components/mn_filters": path.resolve(__dirname, "./app/components/mn_filters.js"),
      "components/mn_poll": path.resolve(__dirname, "./app/components/mn_poll.js"),
      "components/mn_helper": path.resolve(__dirname, "./app/components/mn_helper.js"),
      "components/mn_pool_default": path.resolve(__dirname, "./app/components/mn_pool_default.js"),
      "components/mn_permissions": path.resolve(__dirname, "./app/components/mn_permissions.js"),
      "components/mn_pending_query_keeper": path.resolve(__dirname, "./app/components/mn_pending_query_keeper.js"),
      "components/directives/mn_select/mn_select": path.resolve(__dirname, "./app/components/directives/mn_select/mn_select.js"),
      "components/directives/mn_element_crane/mn_element_crane": path.resolve(__dirname, "./app/components/directives/mn_element_crane/mn_element_crane.js"),
      "components/directives/mn_detail_stats_controller": path.resolve(__dirname, "./app/components/directives/mn_detail_stats_controller.js"),
      "mn_admin/mn_servers_service": path.resolve(__dirname, "./app/mn_admin/mn_servers_service.js"),
      "mn_admin/mn_statistics_service": path.resolve(__dirname, "./app/mn_admin/mn_statistics_service.js"),
      "mn_admin/mn_statistics_description": path.resolve(__dirname, "./app/mn_admin/mn_statistics_description.js"),
      "mn_admin/mn_statistics_chart_directive": path.resolve(__dirname, "./app/mn_admin/mn_statistics_chart_directive.js"),
      "mn_admin/mn_gsi_footer_controller": path.resolve(__dirname, "./app/mn_admin/mn_gsi_footer_controller.js"),
      "mn_admin/mn_documents_service": path.resolve(__dirname, "./app/mn_admin/mn_documents_service.js")
    },
  },
})