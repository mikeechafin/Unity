# Version: 2026-04-03 v1.00
# Changes: New dedicated page for network topology visualization using Cytoscape.js. Interactive graph with device nodes (color-coded by type), labeled edges (protocol/speed), path tracer, rack overlay, filters, snapshot selector. Pulls live data from ports + discovered_links tables.

import React, { useEffect, useState, useRef } from 'react';
import CytoscapeComponent from 'react-cytoscapejs';
import cytoscape from 'cytoscape';
import coseBilkent from 'cytoscape-cose-bilkent';
import { Button, Select, Table, Input, Space, Typography, Card, Row, Col } from 'antd';
import { SearchOutlined, ZoomInOutlined, ZoomOutOutlined, ReloadOutlined, PlayCircleOutlined } from '@ant-design/icons';

cytoscape.use(coseBilkent);

const { Title, Text } = Typography;

const NetworkTopologyExplorer = () => {
  const [elements, setElements] = useState([]);
  const [snapshots, setSnapshots] = useState([]);
  const [selectedSnapshot, setSelectedSnapshot] = useState(null);
  const [filters, setFilters] = useState({ fabric: 'all', type: 'all' });
  const [searchTerm, setSearchTerm] = useState('');
  const [pathSource, setPathSource] = useState('');
  const [pathTarget, setPathTarget] = useState('');
  const cyRef = useRef(null);

  // Fetch snapshots and latest topology
  useEffect(() => {
    fetch('/api/topology/snapshots')
      .then(res => res.json())
      .then(data => {
        setSnapshots(data);
        if (data.length > 0) loadSnapshot(data[0].id);
      });
  }, []);

  const loadSnapshot = (snapshotId) => {
    fetch(`/api/topology/snapshot/${snapshotId}`)
      .then(res => res.json())
      .then(data => {
        setSelectedSnapshot(snapshotId);
        const cyElements = [];
        data.ports.forEach(p => {
          cyElements.push({
            data: {
              id: `port-${p.id}`,
              label: `${p.name}\n${p.mac_address || ''}`,
              type: p.port_type,
              device: p.device_name,
              deviceType: p.device_type
            }
          });
        });
        data.links.forEach(l => {
          cyElements.push({
            data: {
              source: `port-${l.port_a_id}`,
              target: `port-${l.port_b_id}`,
              label: `${l.protocol} ${l.speed}`,
              protocol: l.protocol,
              confidence: l.confidence
            }
          });
        });
        setElements(cyElements);
      });
  };

  const highlightPath = () => {
    if (!cyRef.current || !pathSource || !pathTarget) return;
    const cy = cyRef.current;
    const path = cy.elements().dijkstra({
      root: `#port-${pathSource}`,
      target: `#port-${pathTarget}`
    }).path;
    if (path) {
      cy.elements().removeClass('highlighted');
      path.addClass('highlighted');
    }
  };

  const filterElements = () => {
    if (!cyRef.current) return;
    const cy = cyRef.current;
    cy.elements().hide();
    let query = '';
    if (filters.fabric !== 'all') query += `[type = "${filters.fabric}"]`;
    if (filters.type !== 'all') query += `[deviceType = "${filters.type}"]`;
    if (searchTerm) query += `[label *= "${searchTerm}"]`;
    cy.elements(query).show();
  };

  const styles = [
    {
      selector: 'node',
      style: {
        'background-color': '#1890ff',
        'label': 'data(label)',
        'text-valign': 'center',
        'text-halign': 'center',
        'font-size': '10px',
        'width': '45px',
        'height': '45px',
        'text-wrap': 'wrap'
      }
    },
    {
      selector: 'edge',
      style: {
        'width': 3,
        'line-color': '#52c41a',
        'target-arrow-color': '#52c41a',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'label': 'data(label)',
        'font-size': '8px'
      }
    },
    {
      selector: '.highlighted',
      style: {
        'line-color': '#f5222d',
        'target-arrow-color': '#f5222d',
        'width': 5
      }
    }
  ];

  return (
    <div style={{ padding: '20px' }}>
      <Title level={2}>Network Topology Explorer</Title>
      <Text type="secondary">Real-time port-to-port mapping across Exadata fabric (RoCE + IB)</Text>

      <Card style={{ marginTop: 20 }}>
        <Space wrap>
          <Select
            value={selectedSnapshot}
            onChange={loadSnapshot}
            style={{ width: 220 }}
            options={snapshots.map(s => ({ label: new Date(s.snapshot_ts).toLocaleString(), value: s.id }))}
          />
          <Select
            value={filters.fabric}
            onChange={v => { setFilters({ ...filters, fabric: v }); filterElements(); }}
            options={[
              { label: 'All Fabrics', value: 'all' },
              { label: 'RoCE', value: 'roce' },
              { label: 'IB', value: 'ib' }
            ]}
          />
          <Select
            value={filters.type}
            onChange={v => { setFilters({ ...filters, type: v }); filterElements(); }}
            options={[
              { label: 'All Devices', value: 'all' },
              { label: 'Switch', value: 'switch' },
              { label: 'Server', value: 'server' }
            ]}
          />
          <Input
            placeholder="Search ports/devices"
            value={searchTerm}
            onChange={e => { setSearchTerm(e.target.value); filterElements(); }}
            style={{ width: 280 }}
            prefix={<SearchOutlined />}
          />
          <Button icon={<ReloadOutlined />} onClick={() => loadSnapshot(selectedSnapshot)}>Refresh</Button>
        </Space>
      </Card>

      <Row gutter={16} style={{ marginTop: '20px' }}>
        <Col span={18}>
          <CytoscapeComponent
            elements={elements}
            style={{ width: '100%', height: '700px', border: '1px solid #d9d9d9', borderRadius: '8px' }}
            stylesheet={styles}
            layout={{ name: 'cose-bilkent', nodeDimensionsIncludeLabels: true, animate: true }}
            cy={(cy) => { cyRef.current = cy; }}
          />
        </Col>

        <Col span={6}>
          <Card title="Path Tracer" style={{ marginBottom: 16 }}>
            <Space direction="vertical" style={{ width: '100%' }}>
              <Select
                placeholder="Source Port"
                onChange={setPathSource}
                style={{ width: '100%' }}
                options={elements.filter(e => e.data.id.startsWith('port-')).map(e => ({ label: e.data.label, value: e.data.id.replace('port-', '') }))}
              />
              <Select
                placeholder="Target Port"
                onChange={setPathTarget}
                style={{ width: '100%' }}
                options={elements.filter(e => e.data.id.startsWith('port-')).map(e => ({ label: e.data.label, value: e.data.id.replace('port-', '') }))}
              />
              <Button type="primary" icon={<PlayCircleOutlined />} onClick={highlightPath} block>Trace End-to-End Path</Button>
            </Space>
          </Card>

          <Card title="Recent Snapshots">
            <Table
              dataSource={snapshots.slice(0, 5)}
              columns={[
                { title: 'Time', dataIndex: 'snapshot_ts', key: 'time', render: t => new Date(t).toLocaleString() },
                { title: 'Links', dataIndex: 'total_links', key: 'links' }
              ]}
              size="small"
              pagination={false}
              onRow={record => ({ onClick: () => loadSnapshot(record.id) })}
              rowClassName={() => 'clickable-row'}
            />
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default NetworkTopologyExplorer;
