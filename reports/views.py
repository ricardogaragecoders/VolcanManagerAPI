from django.db.models import Q
from rest_framework.permissions import IsAuthenticated

from common.utils import get_datetime_from_querystring
from common.views import CustomViewSetWithPagination
from reports.models import Report
from reports.serializers import ReportSerializer
from users.permissions import IsVerified, IsOperator


# Create your views here.
class ReportApiView(CustomViewSetWithPagination):
    serializer_class = ReportSerializer
    model_class = Report
    permission_classes = (IsAuthenticated, IsVerified, IsOperator)
    field_pk = 'report_id'

    def get_queryset_filters(self, *args, **kwargs):
        report_types = self.request.query_params.getlist('rtts', [])
        active = self.request.query_params.get('active', 'all')

        profile = self.request.user.profile
        if profile.is_admin(equal=False):
            issuer_id = self.request.query_params.get('issuer_id', '')
        elif profile.is_operator():
            from control.models import Operator
            operator = Operator.objects.filter(profile=profile).values('company__volcan_issuer_id').first()
            issuer_id = operator['company__volcan_issuer_id'] if operator else profile.user.first_name
        else:
            issuer_id = 'sin_emision'

        filters = {'deleted_at__isnull': True}

        initial_date = get_datetime_from_querystring(self.request, 'initial_date', None)
        final_date = get_datetime_from_querystring(self.request, 'final_date', None)

        if initial_date:
            filters['initial_date__gte'] = initial_date

        if final_date:
            filters['final_date__lte'] = final_date

        if len(report_types) > 0:
            filters['report_type__in'] = report_types

        if len(issuer_id) > 0:
            filters['company__volcan_issuer_id'] = issuer_id

        if active != 'all':
            filters['is_active'] = active == 'true'

        return filters

    def get_queryset(self, *args, **kwargs):
        filters = self.get_queryset_filters(*args, **kwargs)
        q = self.request.query_params.get('q', None)
        order_by = self.request.query_params.get('orderBy', 'report_type')
        order_by_desc = self.request.query_params.get('orderByDesc', 'false')

        queryset = self.model_class.objects.select_related(
            'company',
        ).filter(**filters).distinct()

        if q:
            queryset = queryset.filter(
                Q(company__name__icontains=q) |
                Q(report_type__icontains=q)
            ).distinct()

        if not hasattr(self.model_class, order_by):
            order_by = 'created_at'

        order_by_filter = '{0}'.format(order_by if order_by_desc == 'false' else "-%s" % order_by)

        return queryset.order_by(order_by_filter)

    def get_select_related_one(self):
        return ['company', ]

    # def perform_create(self, request, *args, **kwargs):
    #     report = self.serializer.save()
    #     db = MonitorCollection()
    #     user = request.user
    #     db.insert_one({
    #         'instance_id': str(report.unique_id),
    #         'action': 'Generar reporte {}'.format(report.report_type),
    #         'endpoint': request.path,
    #         'description': 'Generacion de reporte',
    #         'user': '{}'.format(user.get_full_name()),
    #         'user_id': user.id,
    #         'email': user.email,
    #         'role': user.profile.role if user.profile else 0,
    #         'program_name': report.program.name,
    #         'program_ID': str(report.program.unique_id),
    #         'updated_at': timezone.localtime(timezone.now())
    #     })
    #     self.make_response_success(data=self.serializer.data)