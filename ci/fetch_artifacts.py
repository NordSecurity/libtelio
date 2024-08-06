import json
import os
import re
import subprocess
import requests
import zipfile
from datetime import datetime


# This script is used to download the latest tagged build artifacts from the GitLab CI pipeline.
class ArtifactsDownloader:
    def __init__(
        self,
        target_os,
        target_arch,
        token,
        commit_sha,
        path_to_save="./",
        repo_dir="./",
        tag_prefix="nightly",
    ):
        self.target_os = target_os
        self.target_arch = target_arch
        self.token = token
        self.commit_sha = commit_sha
        self.path_to_save = path_to_save
        self.repo_dir = repo_dir
        self.tag_prefix = tag_prefix

    def download(self):
        tag, tag_msg = self._get_latest_tag()

        print(f"Selected {tag} for artifact download")
        self._get_pipeline_build_artifacts(tag_msg)

    def _extract_date(self, tag):
        """Extract the date from the tag name."""
        date_char_count = 6

        if self.tag_prefix == "main":
            date_char_count = 10

        date_str = re.search(
            f"{self.tag_prefix}-([0-9]{{{date_char_count}}})", tag
        ).group(1)
        return date_str

    def _get_latest_tag(self):
        """Find the latest tag with the given prefix."""
        subprocess.run(
            ["git", "-C", self.repo_dir, "fetch", "--tags", "--quiet"], check=True
        )

        tags = (
            subprocess.check_output(
                [
                    "git",
                    "-C",
                    self.repo_dir,
                    "tag",
                    "--sort=-creatordate",
                    f"--points-at={self.commit_sha}",
                ]
            )
            .decode()
            .splitlines()
        )
        tags = [tag for tag in tags if tag.startswith(f"{self.tag_prefix}-")]

        latest_tag = None
        latest_date = None

        for tag in tags:
            date_str = self._extract_date(tag)
            if date_str is None:
                continue

            date = datetime.strptime(
                date_str, "%y%m%d" if len(date_str) == 6 else "%y%m%d%H%M"
            )

            if latest_date is None or date > latest_date:
                latest_tag = tag
                latest_date = date

        if latest_tag:
            message = (
                subprocess.check_output(
                    ["git", "-C", self.repo_dir, "tag", "-l", "-n1", latest_tag]
                )
                .decode()
                .strip()
                .split(" ", 1)[1]
            )
            return latest_tag, message

        raise Exception("No suitable build tag was found")

    def _get_remote_path(self) -> str:
        LIBTELIO_BUILD_PROJECT_ID = 6299
        libtelio_env_sec_gitlab_repository = os.environ.get(
            "LIBTELIO_ENV_SEC_GITLAB_REPOSITORY", None
        )

        if libtelio_env_sec_gitlab_repository is None:
            raise ValueError("LIBTELIO_ENV_SEC_GITLAB_REPOSITORY not set.")

        return f"https://{libtelio_env_sec_gitlab_repository}/api/v4/projects/{LIBTELIO_BUILD_PROJECT_ID}"

    def _get_api(self, path, timeout=300):
        with requests.get(
            self._get_remote_path() + path,
            headers={"PRIVATE-TOKEN": self.token if self.token else ""},
            timeout=timeout,
        ) as request:
            request.raise_for_status()
            response_string = request.content.decode("utf-8")
            return response_string

    def _get_artifacts(self, job, timeout=300, unzip=False):
        full_path = self.path_to_save + job["artifacts_file"]["filename"]

        print("Getting artficats for ", job["name"], ", filename: ", full_path)

        r = requests.get(
            self._get_remote_path() + "/jobs/" + str(job["id"]) + "/artifacts",
            headers={"PRIVATE-TOKEN": self.token if self.token else ""},
            timeout=timeout,
        )
        with open(str(full_path), "wb") as f:
            f.write(r.content)

        with zipfile.ZipFile(full_path, "r") as zip_ref:
            zip_ref.extractall(self.path_to_save)

    def _get_pipeline_build_artifacts(self, tag_msg):
        tag_data = json.loads(tag_msg)
        pipeline_id = tag_data["pipeline_id"]

        for job in json.loads(
            self._get_api(
                (
                    f"/pipelines/{pipeline_id}/jobs?per_page=100&include_retried=true&scope=success"
                )
            )
        ):
            # Uniffi bindings
            if (
                job["stage"] == "build"
                and self.target_os == "uniffi"
                and job["name"] == "uniffi-bindings"
            ):
                self._get_artifacts(job)

            # Binary builds
            if (
                job["stage"] == "build"
                and self.target_os in job["name"]
                and self.target_arch in job["name"]
            ):
                self._get_artifacts(job, unzip=True)
