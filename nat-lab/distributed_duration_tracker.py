#!/usr/bin/env python3

import json
import os
import sys
from typing import Dict


class DistributedDurationTracker:
    def __init__(self, base_path: str = "/images/codehub/test_durations"):
        """
        Initialize the distributed duration tracker

        :param base_path: Base directory for storing duration files
        """
        self.base_path = base_path
        os.makedirs(base_path, exist_ok=True)

        # Unique identifier for this node/run
        self.node_id = os.environ.get("CI_NODE_INDEX", "local")

    def _get_node_duration_file(self) -> str:
        """
        Get the path for the current node's duration file

        :return: Path to the node-specific duration file
        """
        return os.path.join(self.base_path, f"node_{self.node_id}_durations.json")

    def _get_compiled_duration_file(self) -> str:
        """
        Get the path for the compiled duration file

        :return: Path to the compiled duration file
        """
        return os.path.join(self.base_path, "compiled_test_durations.json")

    def save_node_durations(self, durations: Dict[str, float]):
        """
        Save durations specific to this node

        :param durations: Dictionary of test names and their durations
        """
        node_file = self._get_node_duration_file()
        with open(node_file, "w") as f:
            json.dump(durations, f, indent=2)
        print(f"Saved node-specific durations to {node_file}")

    def compile_durations(self):
        """
        Compile duration files from all nodes into a single file

        Merging strategy:
        1. Collect all node-specific duration files
        2. Compute weighted average of test durations
        3. Update compiled duration file
        """
        # Find all node duration files
        node_files = [
            os.path.join(self.base_path, f)
            for f in os.listdir(self.base_path)
            if f.startswith("node_") and f.endswith("_durations.json")
        ]

        # Merged duration tracking
        merged_durations: Dict[str, float] = {}
        node_counts: Dict[str, int] = {}

        # Collect and merge durations
        for file_path in node_files:
            try:
                with open(file_path, "r") as f:
                    node_durations = json.load(f)

                for test_name, duration in node_durations.items():
                    if test_name not in merged_durations:
                        merged_durations[test_name] = 0
                        node_counts[test_name] = 0

                    # Weighted moving average
                    merged_durations[test_name] += duration
                    node_counts[test_name] += 1

            except (IOError, json.JSONDecodeError) as e:
                print(f"Error processing {file_path}: {e}", file=sys.stderr)

        # Compute average
        for test_name in merged_durations:
            merged_durations[test_name] /= max(node_counts[test_name], 1)

        # Save compiled durations
        compiled_file = self._get_compiled_duration_file()
        with open(compiled_file, "w") as f:
            json.dump(merged_durations, f, indent=2)

        print(f"Compiled test durations saved to {compiled_file}")
        return merged_durations

    def get_compiled_durations(self) -> Dict[str, float]:
        """
        Retrieve the compiled duration file

        :return: Dictionary of test durations
        """
        compiled_file = self._get_compiled_duration_file()
        try:
            with open(compiled_file, "r") as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError):
            return {}
