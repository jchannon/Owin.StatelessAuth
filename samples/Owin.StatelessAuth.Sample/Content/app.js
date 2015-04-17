(function () {
    'use strict';

    var app = angular.module('owinstatelessauthexample', ['LocalForageModule'])
        .controller('appCtrl', ['$scope', '$localForage', '$http', function ($scope, $localForage, $http) {
            // Start fresh
            $localForage.clearAll();

            $scope.user = 'fred';
            $scope.password = 'securepwd';
            $scope.secureresponse = '';
            $scope.loggedinstatus = 'Not Logged In';

            $scope.getToken = function () {
                $http({
                    method: 'POST',
                    url: '/login',
                    data: {
                        "user": $scope.user,
                        "password": $scope.password,
                    }
                })
                    .success(function (data, status) {
                        console.log('All ok : ' + data);
                        $localForage.setItem('mysecuretoken', JSON.parse(data));
                        $scope.loggedinstatus = 'Logged In';
                    })
                    .error(function (data, status) {
                        console.log('Oops : ' + data);
                    });

            };

            $scope.getsecureresponse = function () {
                $localForage.get('mysecuretoken').then(function (data) {
                    $http({
                        method: 'GET',
                        url: '/',
                        headers: { 'Authorization': data }

                    })
                   .success(function (data, status) {
                       console.log('All secure : ' + data);
                       $scope.secureresponse = data;
                   })
                   .error(function (data, status) {
                       console.log('Oops : ' + data);
                       $scope.secureresponse = "Oops!" + data;
                   });
                });

            };
        }]);

})();
