clear;
files = dir('seq-time');

count_up = 0;
count_down = 0;
count_data = 0;
start_t = 0;
end_t = -1;
interval_t = 1000;
for i = 3 : length(files)
    if files(i).bytes > 0
        res = strfind(files(i).name, '_up');
        if isempty(res)
            count_down = count_down + 1;
        else
            count_up = count_up + 1;
        end
        if strcmp(files(i).name(1:7), 'dl-clie') || strcmp(files(i).name(1:7), 'api-con')
            count_data = count_data + 1;
        end
        
        data = csvread(['seq-time\', files(i).name]);
        d_size = size(data);
        if start_t == -1
%             start_t = data(1, 1);
            end_t = data(d_size(1), 1);
        else
%             if data(1, 1) < start_t
%                 start_t = data(1, 1);
%             end
            if end_t < data(d_size(1), 1);
                end_t = data(d_size(1), 1);
            end
        end
    end
end

fig1 = figure(1);
title('up stream seq-time plot');
xlabel('time(S)'), ylabel('sequence number');
hold on;
names_up = cell(count_up, 1);
pps_up = [];
index_up = 1;

% plot up stream
for i = 3 : length(files)
    if files(i).bytes > 0
        name = files(i).name;
        res = strfind(name, '_down');
        if isempty(res)
            names_up(index_up) = {name};
            data = csvread(['seq-time\', name]);
            if strcmp(name(1:7), 'client-')
                pp = plot((data(:, 1) - start_t) / 1000, data(:, 2), '.b');
            elseif strcmp(name(1:7), 'clientX')
                pp = plot((data(:, 1) - start_t) / 1000, data(:, 2), '.g');
            elseif strcmp(name(1:7), 'd.dropb')
                pp = plot((data(:, 1) - start_t) / 1000, data(:, 2), '.y');
            elseif strcmp(name(1:7), 'dl-clie')
                pp = plot((data(:, 1) - start_t) / 1000, data(:, 2), '.k');
            elseif strcmp(name(1:7), 'notifyX')
                pp = plot((data(:, 1) - start_t) / 1000, data(:, 2), '.r');
            elseif strcmp(name(1:7), 'api.dro')
                pp = plot((data(:, 1) - start_t) / 1000, data(:, 2), '.g');
            elseif strcmp(name(1:7), 'api-con')
                pp = plot((data(:, 1) - start_t) / 1000, data(:, 2), '.k');
            elseif strcmp(name(1:7), 'api-not')
                pp = plot((data(:, 1) - start_t) / 1000, data(:, 2), '.r');
            else
                %disp(name);
                pp = plot((data(:, 1) - start_t) / 1000, data(:, 2), '.b');
            end
            pps_up = [pps_up, pp];
            index_up = index_up + 1;
        end
    end
end
legend(pps_up, names_up);
saveas(fig1, 'up_stream_seq_time_fig.fig');

fig2 = figure(2);
title('down stream seq-time plot');
xlabel('time(S)'), ylabel('sequence number');
hold on;
index_down = 1;
names_down = cell(count_down, 1);
pps_down = [];

% plot down stream
for i = 3 : length(files)
    if files(i).bytes > 0
        name = files(i).name;
        res = strfind(name, '_up');
        if isempty(res)
            names_down(index_down) = {name};
            data = csvread(['seq-time\', name]);
            if strcmp(name(1:7), 'client-')
                pp = plot((data(:, 1) - start_t) / 1000, data(:, 2), '.b');
            elseif strcmp(name(1:7), 'clientX')
                pp = plot((data(:, 1) - start_t) / 1000, data(:, 2), '.g');
            elseif strcmp(name(1:7), 'd.dropb')
                pp = plot((data(:, 1) - start_t) / 1000, data(:, 2), '.y');
            elseif strcmp(name(1:7), 'dl-clie')
                pp = plot((data(:, 1) - start_t) / 1000, data(:, 2), '.k');
            elseif strcmp(name(1:7), 'notifyX')
                pp = plot((data(:, 1) - start_t) / 1000, data(:, 2), '.r');
            elseif strcmp(name(1:7), 'api.dro')
                pp = plot((data(:, 1) - start_t) / 1000, data(:, 2), '.g');
            elseif strcmp(name(1:7), 'api-con')
                pp = plot((data(:, 1) - start_t) / 1000, data(:, 2), '.k');
            elseif strcmp(name(1:7), 'api-not')
                pp = plot((data(:, 1) - start_t) / 1000, data(:, 2), '.r');
            else
                %disp(name);
                pp = plot((data(:, 1) - start_t) / 1000, data(:, 2), '.b');
            end
            pps_down = [pps_down, pp];
            index_down = index_down + 1;
        end
    end
end
legend(pps_down, names_down);
saveas(fig2, 'down_stream_seq_time_fig.fig');

% plot goodput of data stream
goodputs = zeros(count_data, ceil((end_t - start_t) / interval_t));

fig3 = figure(3);
title('goodput-time plot');
xlabel('time(S)'), ylabel('goodput(KB/S)');
hold on;
index_data = 1;
names_data = cell(count_data + 1, 1);
pps_data = [];
for i = 3 : length(files)
    if files(i).bytes > 0
        name = files(i).name;
        if strcmp(name(1:7), 'dl-clie') || strcmp(name(1:7), 'api-con')
            names_data(index_data) = {name};
            data = csvread(['seq-time\', name]);
            
            diff_seq = [];
            diff_t = [];
            diff_seq = [diff_seq 0];
            diff_t = [diff_t data(1, 1)];
            
            former_t = data(1, 1);
            former_j = 1;
            for j = 2 : length(data)
                if data(j, 1) - former_t > interval_t
                    goodput = (data(j, 2) - data(former_j, 2)) / (data(j, 1) - data(former_j, 1));
                    diff_seq = [diff_seq goodput];
                    diff_t = [diff_t data(j, 1)];
                    former_j = j;
                    former_t = data(j, 1);
                end
            end
            diff_t = diff_t - start_t;
            
            for j = 1 : length(diff_t)
                goodputs(index_data, floor(diff_t(j) / interval_t) + 1) = diff_seq(j);
            end
            
%             pp = plot(diff_t / 1000, diff_seq, 'k');
            pp = plot(1:length(goodputs), goodputs(index_data, :), 'k');
            pps_data = [pps_data, pp];
            index_data = index_data + 1;
        end
    end
end

total_goodput = zeros(1, ceil((end_t - start_t) / interval_t));
for i = 1:count_data
    for j = 1:length(total_goodput)
        total_goodput(j) = total_goodput(j) + goodputs(i, j);
    end
end
names_data(index_data) = {'total goodput of all stream'};
pp = plot(1:length(total_goodput), total_goodput, 'k');
% disp(pp);
pps_data = [pps_data, pp];


legend(pps_data, names_data);
saveas(fig3, 'data_stream_goodput_time_fig.fig');