import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { Layout } from '@/components/Layout'
import Dashboard from '@/pages/Dashboard'
import Events from '@/pages/Events'
import Dns from '@/pages/Dns'
import Devices from '@/pages/Devices'
import Blocklist from '@/pages/Blocklist'
import Whitelist from '@/pages/Whitelist'
import Topology from '@/pages/Topology'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/events" element={<Events />} />
          <Route path="/dns" element={<Dns />} />
          <Route path="/devices" element={<Devices />} />
          <Route path="/blocklist" element={<Blocklist />} />
          <Route path="/whitelist" element={<Whitelist />} />
          <Route path="/topology" element={<Topology />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
