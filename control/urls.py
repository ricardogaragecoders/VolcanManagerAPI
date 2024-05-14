from django.urls import path
from control.views import *

urlpatterns = [
    # General
    path('CreacionEnte/', ControlApiView.as_view({'post': 'creation_ente'})),
    path('CreacionEnteSectorizacion/', ControlApiView.as_view({'post': 'creation_ente_sectorizacion'})),
    path('CreacionCtaTar/', ControlApiView.as_view({'post': 'creation_cta_tar'})),
    path('Cuentas/', ControlApiView.as_view({'post': 'consulta_cuenta'})),
    path('Extrafinanciamientos/', ControlApiView.as_view({'post': 'extrafinanciamientos'})),
    path('Intrafinanciamientos/', ControlApiView.as_view({'post': 'intrafinanciamientos'})),
    path('ConsultaTarjetas/', ControlApiView.as_view({'post': 'consulta_tarjetas'})),
    path('CambioPIN/', ControlApiView.as_view({'post': 'cambio_pin'})),
    path('CambioLimites/', ControlApiView.as_view({'post': 'cambio_limites'})),
    path('CambioEstatusTDC/', ControlApiView.as_view({'post': 'cambio_estatus_tdc'})),
    path('ReposicionTarjetas/', ControlApiView.as_view({'post': 'reposicion_tarjetas'})),
    path('GestionTransacciones/', ControlApiView.as_view({'post': 'gestion_transacciones'})),
    path('ConsultaEnte/', ControlApiView.as_view({'post': 'consulta_ente'})),
    path('ConsultaMovimientos/', ControlApiView.as_view({'post': 'consulta_movimientos'})),
    path('ConsultaPuntos/', ControlApiView.as_view({'post': 'consulta_puntos'})),
    path('IntraExtras/', ControlApiView.as_view({'post': 'intra_extras'})),
    path('ConsultaIntraExtraF1/', ControlApiView.as_view({'post': 'consulta_intra_extra_f1'})),
    path('ConsultaTransacionesXFecha/', ControlApiView.as_view({'post': 'consulta_transaciones_x_fecha'})),
    path('ConsultaCvv2/', ControlApiView.as_view({'post': 'consulta_cvv2'})),
    path('ConsultaEstadoCta/', ControlApiView.as_view({'post': 'consulta_estado_cuenta'})),
    path('ConsultaCobranza/', ControlApiView.as_view({'post': 'consulta_cobranza'})),
]
