from pathlib import Path

from vessel.diff import diff_configs
from vessel.utils import skopeo
from vessel.utils.uri import ImageURI


def test_comp(tmp_path: Path):
    """Tests that for two known images, the two known diffs are found."""
    test_image_name = "hello-world:latest"
    test_image_uri = ImageURI(f"docker://{test_image_name}")
    output_path1 = skopeo.skopeo_copy(test_image_uri, str(tmp_path))

    test_image_name = "busybox:latest"
    test_image_uri = ImageURI(f"docker://{test_image_name}")
    output_path2 = skopeo.skopeo_copy(test_image_uri, str(tmp_path))

    diffs = diff_configs.compare_configs(output_path1, output_path2)
    print(f"Diffs: {diffs}")
    assert len(diffs) == 2
