from rest_framework import serializers

from common.models import Status


class SkuReadOnlyMixin(serializers.Serializer):
    sku = serializers.CharField(max_length=150, read_only=True)


class CreatedAndUpdatedReadOnlyMixin(serializers.Serializer):
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)


class CreatedAndUpdatedAndDeletedReadOnlyMixin(CreatedAndUpdatedReadOnlyMixin):
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)
    deleted_at = serializers.DateTimeField(read_only=True)


class StatusSerializer(CreatedAndUpdatedReadOnlyMixin, serializers.ModelSerializer):
    class Meta:
        model = Status
        fields = ('id', 'name')

