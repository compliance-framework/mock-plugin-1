package compliance_framework.mock_enabled

title := "Mock plugin is enabled"

description := "The fixed input of mock-plugin-1 reports the plugin as enabled."

violation contains {"id": "mock-disabled"} if not input.enabled
