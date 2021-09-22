import numpy as np
import sys

class Topsis():
    request_matrics =np.array([ # ユーザ要求を反映した一対比較表 (推論時に特定したアプリケーション要求を反映している?)
        [1, 1, 1/3, 1/3, 1, 1/6, 1],
        [1, 1, 1/3, 1/3, 1, 1/6, 1],
        [3, 3, 1, 1, 3, 1/6, 3],
        [3, 3, 1, 1, 3, 1/6, 3],
        [1, 1, 1/3, 1/3, 1, 1/6, 1],
        [6, 6, 6, 6, 6, 1, 6],
        [1, 1, 1/3, 1/3, 1, 1/6, 1]
        ])
    
    def calc_geometric_mean(self): # ユーザ要求の各行に対する幾何平均
        r = self.request_matrics
        gmean_list = []
        for i in range (0,7):
            product_line = 1
            for j in range (0,7):
                product_line *= r[i, j]    
            gmean = product_line**(1/7)
            gmean_list.append(gmean)   
        return gmean_list


    def calc_request_weights(self): # ユーザー要求から各属性の重みを算出
        weights = []
        gmean_list = self.calc_geometric_mean()
        for i in range (0, 7):
            weights.append(gmean_list[i]/sum(gmean_list))
        return weights


    def line_normalization(self, lines): #アクセス回線の正規化
        denominators = []
        for i in range (lines.shape[1]):
            denominator = 0
            for j in range (lines.shape[0]):
                denominator += lines[j, i]**2
            denominator = denominator**(1/2)
            denominators.append(1/denominator)
        return np.multiply(lines, denominators)
    

    def calc_negaposi(self,flag , t):
        """
        t[0,0], t[1,0]: 使用率       小さい方が理想的
        t[0,1], t[1,1]: 遅延  　     小さい方が理想的
        t[0,2], t[1,2]: 損失  　     小さい方が理想的
        t[0,3], t[1,3]: ジッタ       小さい方が理想的
        t[0,4], t[1,4]: 帯域  　     大きい方が理想的
        t[0,5], t[1,5]: コスト       小さい方が理想的
        t[0,6], t[0,6]: セキュリティ  大きい方が理想的
        """
        if flag == 'positive':
            positives = []
            positives.append(t[1,0]) if t[0,0]>t[1,0] else positives.append(t[0,0])
            positives.append(t[1,1]) if t[0,1]>t[1,1] else positives.append(t[0,1])
            positives.append(t[1,2]) if t[0,2]>t[1,2] else positives.append(t[0,2])
            positives.append(t[1,3]) if t[0,3]>t[1,3] else positives.append(t[0,3])
            positives.append(t[1,4]) if t[0,4]<t[1,4] else positives.append(t[0,4])
            positives.append(t[1,5]) if t[0,5]>t[1,5] else positives.append(t[0,5])
            positives.append(t[1,6]) if t[0,6]<t[1,6] else positives.append(t[0,6])
            return positives
        elif flag == 'negative':
            negatives = []
            negatives.append(t[1,0]) if t[0,0]<t[1,0] else negatives.append(t[0,0])
            negatives.append(t[1,1]) if t[0,1]<t[1,1] else negatives.append(t[0,1])
            negatives.append(t[1,2]) if t[0,2]<t[1,2] else negatives.append(t[0,2])
            negatives.append(t[1,3]) if t[0,3]<t[1,3] else negatives.append(t[0,3])
            negatives.append(t[1,4]) if t[0,4]>t[1,4] else negatives.append(t[0,4])
            negatives.append(t[1,5]) if t[0,5]<t[1,5] else negatives.append(t[0,5])
            negatives.append(t[1,6]) if t[0,6]>t[1,6] else negatives.append(t[0,6])
            return negatives


    def calc_dist(self, v, t):
        dists = [] #d[0]: L1, d[1]: L2... のように対応
        for i in range (t.shape[0]):
            d = (sum((t[i]-v)**2))**(1/2)
            dists.append(d)
        return dists
    
    
    def calc_rank_value(self, d_posi, d_nega):
        return d_nega/(d_posi+d_nega)

"""
推論エンジン
アプリケーション要求の導出(決め打ち)、アクセス回線の絞り込みを行う。

TOPSIS
理想的な回線を決定する。
"""       
def main(argv):
    topsis = Topsis()
    w = topsis.calc_request_weights()
    access_lines = np.array([
        [10, 10, 10, 10, 15, 1, 10], # アクセス回線1 TODO:OpenFlowスイッチから取得
        [10, 10, 10, 10, 30, 3, 10], # アクセス回線2 TODO:OpenFlowスイッチから取得
        ])
    r = topsis.line_normalization(access_lines)
    t = np.multiply(w, r)
    posis = topsis.calc_negaposi('positive', t)
    negas = topsis.calc_negaposi('negative', t)
    d_posis = topsis.calc_dist(posis, t)
    d_negas = topsis.calc_dist(negas, t)
    r_1 = topsis.calc_rank_value(d_posis[0], d_negas[0])
    r_2 = topsis.calc_rank_value(d_posis[1], d_negas[1])
    print('【DEBUG】rank value of L1:{0}'.format(r_1))
    print('【DEBUG】rank value of L2:{0}'.format(r_2))


if __name__ == '__main__':
    sys.exit(main(sys.argv))